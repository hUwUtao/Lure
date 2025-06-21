pub(crate) mod status;

use opentelemetry::metrics::{Counter, Gauge, Meter};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

/// Routing rule with matchers and endpoints, ordered by priority
#[derive(Debug, Clone)]
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
            routes_active: meter.u64_gauge("routes_active").build(),
            routes_resolve: meter.u64_counter("routes_resolve").build(),
            sessions_active: meter.u64_gauge("sessions_active").build(),
            session_create: meter.u64_counter("session_create").build(),
            session_destroy: meter.u64_counter("session_destroy").build(),
        }
    }
}

/// High-performance router with optimized storage and fast domain resolution
#[derive(Debug)]
pub struct RouterInstance {
    /// Active routes indexed by route ID for O(1) access
    active_routes: RwLock<HashMap<u64, Route>>,
    /// Active sessions indexed by client address for O(1) lookup
    active_sessions: RwLock<HashMap<SocketAddr, Arc<Session>>>,
    /// Domain to sorted route IDs mapping for fast resolution
    domain_index: RwLock<HashMap<String, Vec<u64>>>,
    /// Metrics
    metrics: RouterMetrics,
}

impl RouterInstance {
    pub fn new(meter: &Meter) -> Self {
        RouterInstance {
            active_routes: RwLock::new(HashMap::new()),
            active_sessions: RwLock::new(HashMap::new()),
            domain_index: RwLock::new(HashMap::new()),
            metrics: RouterMetrics::new(meter),
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
            routes.insert(route_id, route);
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

    /// Remove a route and clean up indices
    pub async fn remove_route(&self, route_id: u64) {
        // Get route matchers before removal
        let matchers = {
            let routes = self.active_routes.read().await;
            routes.get(&route_id).map(|r| r.matchers.clone())
        };

        if let Some(matchers) = matchers {
            // Remove from active routes
            {
                let mut routes = self.active_routes.write().await;
                routes.remove(&route_id);
            }

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
        self.metrics
            .routes_active
            .record(self.routes_count().await as u64, &[]);
    }

    /// Resolve hostname to endpoint and route pair
    pub async fn resolve(&self, hostname: &str) -> Option<(SocketAddr, Route)> {
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
        &self,
        hostname: &str,
        client_addr: SocketAddr,
    ) -> Option<Arc<Session>> {
        self.metrics.session_create.add(1, &[]);
        let (destination_addr, route) = self.resolve(hostname).await?;

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
            .record(self.session_count().await as u64, &[]);
        Some(session)
    }

    /// Terminate a session
    pub async fn terminate_session(&self, addr: &SocketAddr) {
        self.metrics.session_destroy.add(1, &[]);
        let mut sessions = self.active_sessions.write().await;
        sessions.remove(addr);
        drop(sessions);
        self.metrics
            .sessions_active
            .record(self.session_count().await as u64, &[]);
    }

    /// Get active session count for monitoring
    pub async fn session_count(&self) -> usize {
        let sessions = self.active_sessions.read().await;
        let count = sessions.len();
        drop(sessions);
        count
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
