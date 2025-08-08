pub(crate) mod status;

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use opentelemetry::metrics::{Counter, Gauge, Meter};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, RwLockWriteGuard},
    time::timeout,
};

use crate::telemetry::{get_meter, EventEnvelope, EventServiceInstance, NonObj};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HandshakeOption {
    Vanilla,
    HAProxy,
}

impl Default for HandshakeOption {
    fn default() -> Self {
        Self::Vanilla
    }
}

/// Routing rule with matchers and endpoints, ordered by priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: u64,
    /// Domain patterns or hostnames this route matches
    pub matchers: Vec<String>,
    /// Available endpoint addresses for this route
    pub endpoints: Vec<SocketAddr>,
    /// Whether this route is currently disabled
    pub disabled: bool,
    /// Route priority (higher values take precedence)
    pub priority: u32,
    /// IP Fowarding
    pub handshake: HandshakeOption,
    /// Query override
    pub override_query: bool,
}

/// Client session tracking source, destination, and associated route
#[derive(Debug)]
pub struct Session {
    /// Client's source address
    pub client_addr: SocketAddr,
    /// Selected destination address
    pub destination_addr: SocketAddr,
    /// ID of the route used for this session
    pub route_id: u64,
}

/// RAII handle that terminates the session when dropped
pub struct SessionHandle {
    router: &'static RouterInstance,
    inner: Arc<Session>,
}

impl SessionHandle {
    pub fn new(router: &'static RouterInstance, session: Arc<Session>) -> Self {
        Self {
            router,
            inner: session,
        }
    }
}

impl std::ops::Deref for SessionHandle {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let router = self.router;
        let addr = self.inner.client_addr;
        tokio::spawn(async move {
            let _ = router.terminate_session(&addr).await;
        });
    }
}

#[derive(Debug)]
struct RouterMetrics {
    pub routes_active: Gauge<u64>,
    pub routes_resolve: Counter<u64>,
    pub sessions_active: Gauge<u64>,
    pub session_create: Counter<u64>,
    pub session_destroy: Counter<u64>,
}

impl RouterMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            routes_active: meter.u64_gauge("lure_router_routes_active").build(),
            routes_resolve: meter.u64_counter("lure_router_routes_resolve").build(),
            sessions_active: meter.u64_gauge("lure_router_sessions_active").build(),
            session_create: meter.u64_counter("lure_router_session_create").build(),
            session_destroy: meter.u64_counter("lure_router_session_destroy").build(),
        }
    }
}

/// High-performance router with optimized storage and fast domain resolution
#[derive(Debug)]
pub struct RouterInstance {
    /// Active routes indexed by route ID for O(1) access
    active_routes: RwLock<HashMap<u64, Arc<Route>>>,
    /// Active sessions indexed by client address for O(1) lookup
    active_sessions: RwLock<HashMap<SocketAddr, Arc<Session>>>,
    /// Domain to sorted route IDs mapping for fast resolution
    domain_index: RwLock<HashMap<String, Vec<u64>>>,
    /// Metrics
    metrics: RouterMetrics,
}

impl RouterInstance {
    pub fn new() -> Self {
        RouterInstance {
            active_routes: RwLock::new(HashMap::new()),
            active_sessions: RwLock::new(HashMap::new()),
            domain_index: RwLock::new(HashMap::new()),
            metrics: RouterMetrics::new(&get_meter()),
        }
    }

    /// Apply or update a route configuration
    pub async fn apply_route(&self, route: Route) {
        let route_id = route.id;
        let new_matchers = route.matchers.clone();

        // Check if route exists and get old matchers
        let old_matchers = {
            let routes = self.active_routes.read().await;
            routes.get(&route_id).map(|r| r.matchers.clone())
        };

        // Update domain index
        if let Some(old_matchers) = old_matchers {
            self.update_domain_index(&old_matchers, &new_matchers, route_id)
                .await;
        } else {
            self.add_to_domain_index(&new_matchers, route_id).await;
        }

        // Store the route
        {
            let mut routes = self.active_routes.write().await;
            routes.insert(route_id, Arc::new(route));
        }
        self.metrics
            .routes_active
            .record(self.routes_count().await as u64, &[]);
    }

    /// Add route to domain index with priority-based sorting
    async fn add_to_domain_index(&self, matchers: &[String], route_id: u64) {
        let mut domain_index = self.domain_index.write().await;

        for matcher in matchers {
            let route_ids = domain_index.entry(matcher.clone()).or_default();
            route_ids.push(route_id);
        }

        // Sort all affected entries by priority
        self.sort_routes_by_priority_internal(&mut domain_index)
            .await;
    }

    /// Update domain index when route changes
    async fn update_domain_index(
        &self,
        old_matchers: &[String],
        new_matchers: &[String],
        route_id: u64,
    ) {
        let mut domain_index = self.domain_index.write().await;

        // Remove old matchers
        for matcher in old_matchers {
            if let Some(route_ids) = domain_index.get_mut(matcher) {
                route_ids.retain(|&id| id != route_id);
                if route_ids.is_empty() {
                    domain_index.remove(matcher);
                }
            }
        }

        // Add new matchers
        for matcher in new_matchers {
            let route_ids = domain_index.entry(matcher.clone()).or_default();
            route_ids.push(route_id);
        }

        // Sort all affected entries by priority
        self.sort_routes_by_priority_internal(&mut domain_index)
            .await;
    }

    /// Internal helper to sort routes by priority (requires domain_index write lock)
    async fn sort_routes_by_priority_internal(&self, domain_index: &mut HashMap<String, Vec<u64>>) {
        let routes = self.active_routes.read().await;

        for route_ids in domain_index.values_mut() {
            route_ids.sort_by(|&a, &b| {
                let priority_a = routes.get(&a).map(|r| r.priority).unwrap_or(0);
                let priority_b = routes.get(&b).map(|r| r.priority).unwrap_or(0);
                priority_b.cmp(&priority_a) // Descending order
            });
        }
    }

    async fn remote_route_unlocked(
        &self,
        routes: &mut RwLockWriteGuard<'_, HashMap<u64, Arc<Route>>>,
        route_id: u64,
    ) {
        let matchers = { routes.get(&route_id).map(|r| r.matchers.clone()) };

        if let Some(matchers) = matchers {
            // Remove from active routes

            routes.remove(&route_id);

            // Clean up domain index
            {
                let mut domain_index = self.domain_index.write().await;
                for matcher in &matchers {
                    if let Some(route_ids) = domain_index.get_mut(matcher) {
                        route_ids.retain(|&id| id != route_id);
                        if route_ids.is_empty() {
                            domain_index.remove(matcher);
                        }
                    }
                }
            }
        }
    }

    fn collect_routes_count_unlocked(
        &self,
        routes: &mut RwLockWriteGuard<'_, HashMap<u64, Arc<Route>>>,
    ) {
        self.metrics.routes_active.record(routes.len() as u64, &[]);
    }

    /// Remove a route and clean up indices
    pub async fn remove_route(&self, route_id: u64) {
        // Get route matchers before removal
        let mut routes = self.active_routes.write().await;
        self.remote_route_unlocked(&mut routes, route_id).await;
        self.collect_routes_count_unlocked(&mut routes);
    }

    /// Resolve hostname to endpoint and route pair
    pub async fn resolve(&self, hostname: &str) -> Option<(SocketAddr, Arc<Route>)> {
        self.metrics.routes_resolve.add(1, &[]);
        // Get route IDs for hostname
        let route_ids = {
            let domain_index = self.domain_index.read().await;
            domain_index.get(hostname).cloned()
        }?;

        // Find first enabled route (already sorted by priority)
        let routes = self.active_routes.read().await;
        let best_route = route_ids
            .iter()
            .find_map(|&id| routes.get(&id))
            .filter(|route| !route.disabled)?;

        let endpoint = *best_route.endpoints.first()?;
        Some((endpoint, best_route.clone()))
    }

    /// Create a new session with optimized route lookup
    pub async fn create_session(
        &'static self,
        hostname: &str,
        client_addr: SocketAddr,
    ) -> anyhow::Result<(SessionHandle, Arc<Route>)> {
        self.metrics.session_create.add(1, &[]);
        let (destination_addr, route) = self
            .resolve(hostname)
            .await
            .ok_or(anyhow::anyhow!("Resolve failed"))?;

        let session = Arc::new(Session {
            client_addr,
            destination_addr,
            route_id: route.id,
        });

        // Store session
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(client_addr, session.clone());
            drop(sessions);
        }

        self.metrics
            .sessions_active
            .record(self.session_count().await? as u64, &[]);
        Ok((SessionHandle::new(self, session), route))
    }

    /// Terminate a session
    pub async fn terminate_session(&self, addr: &SocketAddr) -> anyhow::Result<()> {
        self.metrics.session_destroy.add(1, &[]);
        let mut sessions = self.active_sessions.write().await;
        sessions.remove(addr);
        drop(sessions);
        self.metrics
            .sessions_active
            .record(self.session_count().await? as u64, &[]);
        Ok(())
    }

    /// Get active session count for monitoring
    pub async fn session_count(&self) -> anyhow::Result<usize> {
        let sessions = timeout(Duration::from_millis(500), self.active_sessions.read()).await?;
        let count = sessions.len();
        drop(sessions);
        Ok(count)
    }

    /// Get active route count for monitoring
    pub async fn routes_count(&self) -> usize {
        let routes = self.active_routes.read().await;
        routes.len()
    }

    /// Get session by client address
    pub async fn get_session(&self, client_addr: &SocketAddr) -> Option<Arc<Session>> {
        let sessions = self.active_sessions.read().await;
        sessions.get(client_addr).cloned()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RouteReport {
    active: u64,
}

#[async_trait]
impl crate::telemetry::event::EventHook<EventEnvelope, EventEnvelope> for RouterInstance {
    async fn on_handshake(&self) -> Option<EventEnvelope> {
        self.session_count()
            .await
            .map(|count| {
                EventEnvelope::HandshakeRoute(RouteReport {
                    active: count as u64,
                })
            })
            .ok()
    }

    async fn on_event(
        &self,
        handle: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        match event {
            EventEnvelope::SetRoute(route) => {
                self.apply_route(route.to_owned()).await;
            }
            EventEnvelope::FlushRoute(_) => {
                let keys = {
                    let routes = self.active_routes.read().await;
                    routes.keys().cloned().collect::<Vec<_>>()
                };
                let mut routes = self.active_routes.write().await;
                for k in keys {
                    self.remote_route_unlocked(&mut routes, k.to_owned()).await;
                }
                self.collect_routes_count_unlocked(&mut routes);
            }
            EventEnvelope::ListRouteRequest(_) => {
                let routes = self.active_routes.read().await;
                let mut routes_c: Vec<Route> = Vec::with_capacity(routes.len());
                for a in routes.values() {
                    let a = a.as_ref().clone();
                    routes_c.push(a);
                }
                handle
                    .produce_event(EventEnvelope::ListRouteResponse(NonObj::new(routes_c)))
                    .await?;
            }
            EventEnvelope::RemoveRoute(id) => {
                self.remove_route(id.id).await;
            }
            _ => {}
        }
        Ok(())
    }
}
