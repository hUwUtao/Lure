use std::{collections::HashMap, fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use fake_serialize::FakeSerialize;
use log::debug;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, RwLockWriteGuard},
    time::timeout,
};

use crate::{
    metrics::RouterMetrics,
    telemetry::{EventEnvelope, EventServiceInstance, NonObj, get_meter},
};

mod attr;
pub use attr::RouteAttr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Copy)]
pub enum RouteFlags {
    Disabled,
    CacheQuery,
    OverrideQuery,
    ProxyProtocol,
}

/// Routing rule with matchers and endpoints, ordered by priority
#[derive(Default, Debug, Clone, FakeSerialize, Deserialize)]
pub struct Route {
    pub id: u64,
    /// Zone ID, to identify by a global group
    pub zone: u64,
    /// Route priority
    pub priority: i32,
    /// Route flags
    pub flags: attr::RouteAttr,
    /// Domain patterns or hostnames this route matches
    pub matchers: Vec<String>,
    /// Available endpoint addresses for this route
    pub endpoints: Vec<SocketAddr>,
}

impl Route {
    #[inline]
    fn read_flag(&self, flag: RouteFlags) -> bool {
        self.flags.contains(flag)
    }

    #[inline]
    pub fn disabled(&self) -> bool {
        self.read_flag(RouteFlags::Disabled)
    }

    #[inline]
    pub fn proxied(&self) -> bool {
        self.read_flag(RouteFlags::ProxyProtocol)
    }
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

#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub endpoint: SocketAddr,
    pub route: Arc<Route>,
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
            .record_routes_active(self.routes_count().await as u64);
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
        self.metrics.record_routes_active(routes.len() as u64);
    }

    /// Clear all routes and indices.
    pub async fn clear_routes(&self) {
        let keys = {
            let routes = self.active_routes.read().await;
            routes.keys().cloned().collect::<Vec<_>>()
        };
        let mut routes = self.active_routes.write().await;
        for key in keys {
            self.remote_route_unlocked(&mut routes, key).await;
        }
        self.collect_routes_count_unlocked(&mut routes);
    }

    /// Remove a route and clean up indices
    pub async fn remove_route(&self, route_id: u64) {
        // Get route matchers before removal
        let mut routes = self.active_routes.write().await;
        self.remote_route_unlocked(&mut routes, route_id).await;
        self.collect_routes_count_unlocked(&mut routes);
    }

    /// Resolve hostname to endpoint and route pair
    pub async fn resolve(&self, hostname: &str) -> Option<ResolvedRoute> {
        self.metrics.record_routes_resolve();
        // Try exact match first using domain index
        if let Some(route_ids) = {
            let domain_index = self.domain_index.read().await;
            domain_index.get(hostname).cloned()
        } {
            let routes = self.active_routes.read().await;
            let best_route = route_ids
                .iter()
                .find_map(|&id| routes.get(&id))
                .filter(|route| !route.disabled())?
                .clone();

            let endpoint = *best_route.endpoints.first()?;
            return Some(ResolvedRoute {
                endpoint,
                route: best_route,
            });
        }

        // Fallback to wildcard matchers
        let routes = self.active_routes.read().await;
        let mut best: Option<ResolvedRoute> = None;

        for route in routes.values() {
            if route.disabled() {
                continue;
            }
            for matcher in &route.matchers {
                if let Some(port) = Self::match_wildcard(matcher, hostname) {
                    let mut endpoint = *route.endpoints.first()?;
                    if endpoint.port() == 0 {
                        endpoint.set_port(port);
                    }

                    match &best {
                        Some(existing) if existing.route.priority >= route.priority => {}
                        _ => {
                            best = Some(ResolvedRoute {
                                endpoint,
                                route: route.clone(),
                            })
                        }
                    }
                    break;
                }
            }
        }

        best
    }

    fn match_wildcard(matcher: &str, hostname: &str) -> Option<u16> {
        let star = matcher.find('*')?;
        let prefix = &matcher[..star];
        let suffix = &matcher[star + 1..];

        if !hostname.ends_with(suffix) {
            return None;
        }

        let value_part = &hostname[..hostname.len() - suffix.len()];

        let dash = prefix.find('-')?;
        let start = prefix[..dash].parse::<u16>().ok()?;
        let end = prefix[dash + 1..].parse::<u16>().ok()?;
        let value = value_part.parse::<u16>().ok()?;

        if value >= start && value <= end {
            Some(value)
        } else {
            None
        }
    }

    pub async fn create_session_with_resolved(
        &'static self,
        resolved: &ResolvedRoute,
        client_addr: SocketAddr,
    ) -> anyhow::Result<(SessionHandle, Arc<Route>)> {
        self.metrics.record_session_create();
        let session = Arc::new(Session {
            client_addr,
            destination_addr: resolved.endpoint,
            route_id: resolved.route.id,
        });

        // Store session
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(client_addr, session.clone());
            drop(sessions);
        }

        self.metrics
            .record_sessions_active(self.session_count().await? as u64);
        Ok((SessionHandle::new(self, session), resolved.route.clone()))
    }

    /// Terminate a session
    pub async fn terminate_session(&self, addr: &SocketAddr) -> anyhow::Result<()> {
        self.metrics.record_session_destroy();
        let mut sessions = self.active_sessions.write().await;
        sessions.remove(addr);
        drop(sessions);
        self.metrics
            .record_sessions_active(self.session_count().await? as u64);
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

    // No longer meant to emit
    // /// Get session by client address
    // pub async fn get_session(&self, client_addr: &SocketAddr) -> Option<Arc<Session>> {
    //     let sessions = self.active_sessions.read().await;
    //     sessions.get(client_addr).cloned()
    // }
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
                debug!("Setting route: {:?}", route);
                let route = route.to_owned();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wildcard_resolve_replaces_port() {
        let router = RouterInstance::new();
        let route = Route {
            id: 1,
            matchers: vec!["10000-10245*.abc.xyz.com".to_string()],
            endpoints: vec!["123.245.122.21:0".parse().unwrap()],
            ..Default::default()
        };
        router.apply_route(route).await;
        let resolved = router.resolve("10241.abc.xyz.com").await.unwrap();
        assert_eq!(resolved.endpoint, "123.245.122.21:10241".parse().unwrap());
    }
    #[tokio::test]
    async fn route_disabled_flag_works_correctly() {
        let router = RouterInstance::new();

        // Test disabled flag
        let disabled_route = Route {
            id: 1,
            matchers: vec!["example.com".to_string()],
            endpoints: vec!["127.0.0.1:8080".parse().unwrap()],
            flags: attr::RouteAttr::from(RouteFlags::Disabled),
            ..Default::default()
        };
        router.apply_route(disabled_route).await;

        // Disabled route should not resolve
        let resolved = router.resolve("example.com").await;
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn route_proxy_and_normal_flags_work_correctly() {
        let router = RouterInstance::new();

        // Test proxy protocol flag
        let proxied_route = Route {
            id: 2,
            matchers: vec!["proxy.example.com".to_string()],
            endpoints: vec!["127.0.0.1:25565".parse().unwrap()],
            flags: attr::RouteAttr::from(RouteFlags::ProxyProtocol),
            ..Default::default()
        };
        router.apply_route(proxied_route).await;

        let resolved = router.resolve("proxy.example.com").await.unwrap();
        assert!(resolved.route.proxied());
        assert!(!resolved.route.disabled());

        // Test route with no flags
        let normal_route = Route {
            id: 3,
            matchers: vec!["normal.example.com".to_string()],
            endpoints: vec!["127.0.0.1:25565".parse().unwrap()],
            flags: attr::RouteAttr::from_u64(0),
            ..Default::default()
        };
        router.apply_route(normal_route).await;

        let resolved = router.resolve("normal.example.com").await.unwrap();
        assert!(!resolved.route.proxied());
        assert!(!resolved.route.disabled());
    }
}
