use std::{
    collections::HashMap,
    fmt::Debug,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use fake_serialize::{FakeDeserialize, FakeSerialize};
use log::debug;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, RwLockWriteGuard, mpsc},
    time::{MissedTickBehavior, interval, timeout},
};

use crate::{
    metrics::RouterMetrics,
    telemetry::{EventEnvelope, EventServiceInstance, NonObj, get_meter},
    utils::spawn_named,
};

mod attr;
mod dest;
mod endpoint;
pub(crate) mod inspect;
mod profile;
pub use attr::RouteAttr;
pub use dest::Destination;
pub use endpoint::{Endpoint, TunnelOpt};
pub use profile::Profile;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Copy)]
pub enum RouteFlags {
    Disabled,
    CacheQuery,
    OverrideQuery,
    ProxyProtocol,
    PreserveHost,
    Tunnel,
}

/// Authorization mode for tunnel routes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// No authentication required - generates random identifier for tracking
    Public,
    /// Any valid registered token can access
    Protected,
    /// Only specific tokens (by key_id) can access
    Restricted { allowed_tokens: Vec<[u8; 8]> },
}

impl Default for AuthMode {
    fn default() -> Self {
        AuthMode::Protected
    }
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
    /// Optional tunnel token (32-byte identifier)
    pub tunnel_token: Option<[u8; 32]>,
    /// Tunnel authentication mode
    #[serde(skip)]
    pub auth_mode: AuthMode,
    /// Domain patterns or hostnames this route matches
    pub matchers: Vec<String>,
    /// Available endpoint specifications for this route
    pub endpoints: Vec<Endpoint>,
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

    #[inline]
    pub fn preserve_host(&self) -> bool {
        self.read_flag(RouteFlags::PreserveHost)
    }

    #[inline]
    pub fn tunnel(&self) -> bool {
        self.read_flag(RouteFlags::Tunnel)
    }
}

/// Client session tracking source, destination, and associated route
#[derive(Debug, FakeDeserialize)]
pub struct Session {
    /// Session ID (monotonic per instance)
    pub id: u64,
    /// Client's source address
    pub client_addr: SocketAddr,
    /// Selected destination address
    pub destination_addr: SocketAddr,
    /// Resolved endpoint host name (unresolved form from config)
    pub endpoint_host: String,
    /// ID of the route used for this session
    pub route_id: u64,
    /// Tenant/zone ID
    pub zone: u64,
    /// Per-session inspection state (traffic + attributes)
    pub inspect: Arc<inspect::SessionInspectState>,
    /// Profile
    pub profile: Arc<Profile>,
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let attributes = self
            .inspect
            .attributes
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        let view = inspect::inspect_session_to_view(
            self,
            self.client_addr.to_string(),
            self.destination_addr.to_string(),
            self.endpoint_host.clone(),
            attributes,
        );
        view.serialize(serializer)
    }
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
        // Drop can run outside a Tokio runtime during shutdown/teardown; don't panic.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = router.terminate_session(&addr).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub endpoint: SocketAddr,
    pub endpoint_host: String,
    pub tunnel: TunnelOpt,
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
    metrics: Arc<RouterMetrics>,
    metrics_tx: mpsc::UnboundedSender<RouterMetricsMessage>,
    /// Incrementing cursor used for naïve load balancing over resolved endpoints
    balancer_cursor: AtomicU64,
    /// Inspection registry and fast-path counters
    inspect: Arc<inspect::InspectRegistry>,
}

#[derive(Debug)]
enum RouterMetricsMessage {
    RoutesActive(u64),
    SessionsActive(u64),
}

impl Default for RouterInstance {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterInstance {
    pub fn new() -> Self {
        let metrics = Arc::new(RouterMetrics::new(&get_meter()));
        let (metrics_tx, metrics_rx) = mpsc::unbounded_channel();
        spawn_named(
            "Router metrics",
            Self::drive_metrics(metrics.clone(), metrics_rx),
        )
        .expect("Cannot spawn task");

        RouterInstance {
            active_routes: RwLock::new(HashMap::new()),
            active_sessions: RwLock::new(HashMap::new()),
            domain_index: RwLock::new(HashMap::new()),
            metrics,
            metrics_tx,
            balancer_cursor: AtomicU64::new(0),
            inspect: Arc::new(inspect::InspectRegistry::new()),
        }
    }

    pub fn set_instance_name(&self, inst: String) {
        self.inspect.set_instance_name(inst);
    }

    /// Apply or update a route configuration
    pub async fn apply_route(&self, route: Route) {
        let route_id = route.id;
        let zone_id = route.zone;
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
        let total = {
            let mut routes = self.active_routes.write().await;
            routes.insert(route_id, Arc::new(route));
            routes.len() as u64
        };
        let _ = self.inspect.ensure_route(route_id, zone_id).await;
        let _ = self.inspect.ensure_tenant(zone_id).await;
        self.publish_routes_active(total);
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
        let total = routes.len() as u64;
        self.publish_routes_active(total);
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
        let routes = self.active_routes.read().await;

        // Exact match via domain index (already sorted by priority)
        if let Some(route_ids) = {
            let index = self.domain_index.read().await;
            index.get(hostname).cloned()
        } {
            for id in route_ids {
                if let Some(route) = routes.get(&id).filter(|route| !route.disabled())
                    && let Some(resolved) = self.resolve_with_route(route.clone(), None)
                {
                    return Some(resolved);
                }
            }
        }

        // Wildcard match (prefer highest priority)
        let mut best: Option<(i32, ResolvedRoute)> = None;
        for route in routes.values() {
            if route.disabled() {
                continue;
            }

            let port_override = route
                .matchers
                .iter()
                .find_map(|matcher| Self::match_wildcard(matcher, hostname));

            if let Some(port) = port_override
                && let Some(resolved) = self.resolve_with_route(route.clone(), Some(port))
            {
                let priority = resolved.route.priority;
                if best.as_ref().is_none_or(|(p, _)| priority > *p) {
                    best = Some((priority, resolved));
                }
            }
        }

        best.map(|(_, resolved)| resolved)
    }

    fn resolve_with_route(
        &self,
        route: Arc<Route>,
        port_override: Option<u16>,
    ) -> Option<ResolvedRoute> {
        self.select_balanced_endpoint(route.as_ref(), port_override)
            .map(|(endpoint_host, endpoint, tunnel)| ResolvedRoute {
                endpoint,
                endpoint_host,
                tunnel,
                route,
            })
    }

    fn next_balance_index(&self) -> u64 {
        self.balancer_cursor.fetch_add(1, Ordering::Relaxed)
    }

    fn select_balanced_endpoint(
        &self,
        route: &Route,
        port_override: Option<u16>,
    ) -> Option<(String, SocketAddr, TunnelOpt)> {
        let mut candidates: Vec<(Arc<str>, SocketAddr, TunnelOpt)> = Vec::new();

        for destination in &route.endpoints {
            if let Ok(resolved) = destination.destination().resolve() {
                for (host, mut addr) in resolved {
                    if let Some(port) = port_override
                        && addr.port() == 0
                    {
                        addr.set_port(port);
                    }
                    candidates.push((host, addr, destination.tunnel()));
                }
            }
        }

        if candidates.is_empty() {
            return None;
        }

        let idx = (self.next_balance_index() % candidates.len() as u64) as usize;
        let (host, addr, tunnel) = &candidates[idx];
        Some((host.to_string(), *addr, *tunnel))
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
        hostname: &str,
        profile: Arc<Profile>,
    ) -> anyhow::Result<(SessionHandle, Arc<Route>)> {
        self.metrics.record_session_create();
        let id = self.inspect.next_session_id();
        let zone = resolved.route.zone;
        let route_stats = self.inspect.ensure_route(resolved.route.id, zone).await;
        let tenant_stats = self.inspect.ensure_tenant(zone).await;

        route_stats.inc_active();
        tenant_stats.inc_active();

        let inspect_state = Arc::new(inspect::SessionInspectState::new(
            id,
            zone,
            resolved.route.id,
            hostname.to_string(),
            route_stats,
            tenant_stats,
            self.inspect.instance(),
        ));

        let session = Arc::new(Session {
            id,
            zone,
            client_addr,
            destination_addr: resolved.endpoint,
            endpoint_host: resolved.endpoint_host.clone(),
            route_id: resolved.route.id,
            inspect: inspect_state,
            profile,
        });

        // Store session
        let total = {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(client_addr, session.clone());
            sessions.len() as u64
        };
        self.publish_sessions_active(total);

        Ok((SessionHandle::new(self, session), resolved.route.clone()))
    }

    /// Terminate a session
    pub async fn terminate_session(&self, addr: &SocketAddr) -> anyhow::Result<()> {
        self.metrics.record_session_destroy();
        let mut sessions = self.active_sessions.write().await;
        if let Some(session) = sessions.remove(addr) {
            session.inspect.route.dec_active();
            session.inspect.tenant.dec_active();
        }
        let total = sessions.len() as u64;
        drop(sessions);
        self.publish_sessions_active(total);
        Ok(())
    }

    /// Get active session count for monitoring
    pub async fn session_count(&self) -> anyhow::Result<usize> {
        let sessions = timeout(Duration::from_millis(500), self.active_sessions.read()).await?;
        let count = sessions.len();
        drop(sessions);
        Ok(count)
    }

    pub async fn inspect_sessions(&self) -> Vec<crate::telemetry::inspect::SessionInspect> {
        let sessions = match timeout(Duration::from_millis(500), self.active_sessions.read()).await
        {
            Ok(sessions) => sessions,
            Err(_) => return Vec::new(),
        };

        let mut views = Vec::with_capacity(sessions.len());
        for session in sessions.values() {
            let attributes = session.inspect.attributes.read().await.clone();
            views.push(inspect::inspect_session_to_view(
                session,
                session.client_addr.to_string(),
                session.destination_addr.to_string(),
                session.endpoint_host.clone(),
                attributes,
            ));
        }
        views
    }

    pub async fn inspect_stats(&self) -> inspect::StatsSnapshot {
        let instance = self.inspect.snapshot_instance();
        let tenants = self.inspect.snapshot_tenants().await;
        let routes = self.inspect.snapshot_routes().await;

        let sessions_lock =
            match timeout(Duration::from_millis(500), self.active_sessions.read()).await {
                Ok(sessions) => sessions,
                Err(_) => {
                    return inspect::StatsSnapshot {
                        instance,
                        tenants,
                        routes,
                        sessions: Vec::new(),
                    };
                }
            };

        let sessions = sessions_lock
            .values()
            .map(|session| session.inspect.session_stats_snapshot())
            .collect();

        inspect::StatsSnapshot {
            instance,
            tenants,
            routes,
            sessions,
        }
    }

    /// Get active route count for monitoring
    fn publish_routes_active(&self, total: u64) {
        self.inspect.instance().set_routes_active(total);
        let _ = self
            .metrics_tx
            .send(RouterMetricsMessage::RoutesActive(total));
    }

    fn publish_sessions_active(&self, total: u64) {
        self.inspect.instance().set_sessions_active(total);
        let _ = self
            .metrics_tx
            .send(RouterMetricsMessage::SessionsActive(total));
    }

    async fn drive_metrics(
        metrics: Arc<RouterMetrics>,
        mut rx: mpsc::UnboundedReceiver<RouterMetricsMessage>,
    ) {
        let mut latest_routes: Option<u64> = None;
        let mut latest_sessions: Option<u64> = None;
        let mut dirty = false;
        let mut ticker = interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(RouterMetricsMessage::RoutesActive(total)) => {
                            metrics.record_routes_active(total);
                            latest_routes = Some(total);
                            dirty = true;
                        }
                        Some(RouterMetricsMessage::SessionsActive(total)) => {
                            metrics.record_sessions_active(total);
                            latest_sessions = Some(total);
                            dirty = true;
                        }
                        None => break,
                    }
                }
                _ = ticker.tick() => {
                    if dirty {
                        let routes = latest_routes.unwrap_or(0);
                        let sessions = latest_sessions.unwrap_or(0);
                        debug!(
                            "router metrics snapshot: routes_active={}, sessions_active={}",
                            routes, sessions
                        );
                        dirty = false;
                    }
                }
            }
        }

        if dirty {
            let routes = latest_routes.unwrap_or(0);
            let sessions = latest_sessions.unwrap_or(0);
            debug!(
                "router metrics snapshot (final): routes_active={}, sessions_active={}",
                routes, sessions
            );
        }
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
    use std::future::Future;

    use super::*;

    async fn run_in_local<F, T>(future: F) -> T
    where
        F: Future<Output = T>,
    {
        tokio::task::LocalSet::new().run_until(future).await
    }

    #[tokio::test]
    async fn wildcard_resolve_replaces_port() {
        run_in_local(async {
            let router = RouterInstance::new();
            let route = Route {
                id: 1,
                matchers: vec!["10000-10245*.abc.xyz.com".to_string()],
                endpoints: vec![Endpoint::parse("123.245.122.21:0").unwrap()],
                ..Default::default()
            };
            router.apply_route(route).await;
            let resolved = router.resolve("10241.abc.xyz.com").await.unwrap();
            assert_eq!(resolved.endpoint, "123.245.122.21:10241".parse().unwrap());
        })
        .await;
    }
    #[tokio::test]
    async fn route_disabled_flag_works_correctly() {
        run_in_local(async {
            let router = RouterInstance::new();

            // Test disabled flag
            let disabled_route = Route {
                id: 1,
                matchers: vec!["example.com".to_string()],
                endpoints: vec![Endpoint::parse("127.0.0.1:8080").unwrap()],
                flags: attr::RouteAttr::from(RouteFlags::Disabled),
                ..Default::default()
            };
            router.apply_route(disabled_route).await;

            // Disabled route should not resolve
            let resolved = router.resolve("example.com").await;
            assert!(resolved.is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn route_proxy_and_normal_flags_work_correctly() {
        run_in_local(async {
            let router = RouterInstance::new();

            // Test proxy protocol flag
            let proxied_route = Route {
                id: 2,
                matchers: vec!["proxy.example.com".to_string()],
                endpoints: vec![Endpoint::parse("127.0.0.1:25565").unwrap()],
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
                endpoints: vec![Endpoint::parse("127.0.0.1:25565").unwrap()],
                flags: attr::RouteAttr::from_u64(0),
                ..Default::default()
            };
            router.apply_route(normal_route).await;

            let resolved = router.resolve("normal.example.com").await.unwrap();
            assert!(!resolved.route.proxied());
            assert!(!resolved.route.disabled());
        })
        .await;
    }

    #[tokio::test]
    async fn resolve_load_balances_across_endpoints() {
        run_in_local(async {
            let router = RouterInstance::new();
            let route = Route {
                id: 10,
                matchers: vec!["balanced.example.com".to_string()],
                endpoints: vec![
                    Endpoint::parse("10.0.0.1:25565").unwrap(),
                    Endpoint::parse("10.0.0.2:25565").unwrap(),
                ],
                ..Default::default()
            };

            router.apply_route(route).await;

            let first = router.resolve("balanced.example.com").await.unwrap();
            let second = router.resolve("balanced.example.com").await.unwrap();

            assert_ne!(first.endpoint, second.endpoint);
        })
        .await;
    }
}
