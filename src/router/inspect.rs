use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime},
};

use serde::Serialize;
use tokio::sync::RwLock;

use crate::{
    telemetry::inspect::{
        InstanceStats, RouteStats, SessionAttributes, SessionInspect, SessionStats, TenantStats,
        TrafficCounters,
    },
    utils::UnsafeCounterU64,
};

#[derive(Debug)]
pub struct TrafficCountersAtomic {
    c2s_bytes: UnsafeCounterU64,
    s2c_bytes: UnsafeCounterU64,
    c2s_chunks: UnsafeCounterU64,
    s2c_chunks: UnsafeCounterU64,
    last_sample_ms: UnsafeCounterU64,
    last_c2s_bytes: UnsafeCounterU64,
    last_s2c_bytes: UnsafeCounterU64,
}

impl TrafficCountersAtomic {
    pub fn new() -> Self {
        Self {
            c2s_bytes: UnsafeCounterU64::default(),
            s2c_bytes: UnsafeCounterU64::default(),
            c2s_chunks: UnsafeCounterU64::default(),
            s2c_chunks: UnsafeCounterU64::default(),
            last_sample_ms: UnsafeCounterU64::default(),
            last_c2s_bytes: UnsafeCounterU64::default(),
            last_s2c_bytes: UnsafeCounterU64::default(),
        }
    }

    pub fn record_c2s(&self, bytes: u64) {
        self.c2s_chunks.inc(1);
        self.c2s_bytes.inc(bytes);
    }

    pub fn record_s2c(&self, bytes: u64) {
        self.s2c_chunks.inc(1);
        self.s2c_bytes.inc(bytes);
    }

    pub fn snapshot(&self) -> TrafficCounters {
        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;
        let c2s_bytes = self.c2s_bytes.load();
        let s2c_bytes = self.s2c_bytes.load();

        let prev_ms = self.last_sample_ms.swap(now_ms);
        let prev_c2s = self.last_c2s_bytes.swap(c2s_bytes);
        let prev_s2c = self.last_s2c_bytes.swap(s2c_bytes);

        let (c2s_bps, s2c_bps) = if prev_ms == 0 || now_ms <= prev_ms {
            (0, 0)
        } else {
            let delta_ms = now_ms - prev_ms;
            let c2s = c2s_bytes.saturating_sub(prev_c2s).saturating_mul(1000) / delta_ms;
            let s2c = s2c_bytes.saturating_sub(prev_s2c).saturating_mul(1000) / delta_ms;
            (c2s, s2c)
        };
        TrafficCounters {
            c2s_bytes,
            s2c_bytes,
            c2s_chunks: self.c2s_chunks.load(),
            s2c_chunks: self.s2c_chunks.load(),
            c2s_bps,
            s2c_bps,
        }
    }
}

impl Default for TrafficCountersAtomic {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct TrafficCountersShared {
    c2s_bytes: AtomicU64,
    s2c_bytes: AtomicU64,
    c2s_chunks: AtomicU64,
    s2c_chunks: AtomicU64,
    last_sample_ms: AtomicU64,
    last_c2s_bytes: AtomicU64,
    last_s2c_bytes: AtomicU64,
}

impl TrafficCountersShared {
    pub fn new() -> Self {
        Self {
            c2s_bytes: AtomicU64::new(0),
            s2c_bytes: AtomicU64::new(0),
            c2s_chunks: AtomicU64::new(0),
            s2c_chunks: AtomicU64::new(0),
            last_sample_ms: AtomicU64::new(0),
            last_c2s_bytes: AtomicU64::new(0),
            last_s2c_bytes: AtomicU64::new(0),
        }
    }

    pub fn record_c2s(&self, bytes: u64, chunks: u64) {
        self.c2s_chunks.fetch_add(chunks, Ordering::Relaxed);
        self.c2s_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_s2c(&self, bytes: u64, chunks: u64) {
        self.s2c_chunks.fetch_add(chunks, Ordering::Relaxed);
        self.s2c_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TrafficCounters {
        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;
        let c2s_bytes = self.c2s_bytes.load(Ordering::Relaxed);
        let s2c_bytes = self.s2c_bytes.load(Ordering::Relaxed);

        let prev_ms = self.last_sample_ms.swap(now_ms, Ordering::Relaxed);
        let prev_c2s = self.last_c2s_bytes.swap(c2s_bytes, Ordering::Relaxed);
        let prev_s2c = self.last_s2c_bytes.swap(s2c_bytes, Ordering::Relaxed);

        let (c2s_bps, s2c_bps) = if prev_ms == 0 || now_ms <= prev_ms {
            (0, 0)
        } else {
            let delta_ms = now_ms - prev_ms;
            let c2s = c2s_bytes.saturating_sub(prev_c2s).saturating_mul(1000) / delta_ms;
            let s2c = s2c_bytes.saturating_sub(prev_s2c).saturating_mul(1000) / delta_ms;
            (c2s, s2c)
        };
        TrafficCounters {
            c2s_bytes,
            s2c_bytes,
            c2s_chunks: self.c2s_chunks.load(Ordering::Relaxed),
            s2c_chunks: self.s2c_chunks.load(Ordering::Relaxed),
            c2s_bps,
            s2c_bps,
        }
    }
}

impl Default for TrafficCountersShared {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct RouteStatsAtomic {
    pub id: u64,
    zone: AtomicU64,
    active_sessions: AtomicU64,
    traffic: TrafficCountersShared,
}

impl RouteStatsAtomic {
    fn new(id: u64, zone: u64) -> Self {
        Self {
            id,
            zone: AtomicU64::new(zone),
            active_sessions: AtomicU64::new(0),
            traffic: TrafficCountersShared::new(),
        }
    }

    fn set_zone(&self, zone: u64) {
        self.zone.store(zone, Ordering::Relaxed);
    }

    pub fn record_c2s(&self, bytes: u64, chunks: u64) {
        self.traffic.record_c2s(bytes, chunks);
    }

    pub fn record_s2c(&self, bytes: u64, chunks: u64) {
        self.traffic.record_s2c(bytes, chunks);
    }

    pub fn inc_active(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> RouteStats {
        RouteStats {
            id: self.id,
            zone: self.zone.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            traffic: self.traffic.snapshot(),
        }
    }
}

#[derive(Debug)]
pub struct TenantStatsAtomic {
    pub zone: u64,
    active_sessions: AtomicU64,
    traffic: TrafficCountersShared,
}

impl TenantStatsAtomic {
    fn new(zone: u64) -> Self {
        Self {
            zone,
            active_sessions: AtomicU64::new(0),
            traffic: TrafficCountersShared::new(),
        }
    }

    pub fn record_c2s(&self, bytes: u64, chunks: u64) {
        self.traffic.record_c2s(bytes, chunks);
    }

    pub fn record_s2c(&self, bytes: u64, chunks: u64) {
        self.traffic.record_s2c(bytes, chunks);
    }

    pub fn inc_active(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> TenantStats {
        TenantStats {
            zone: self.zone,
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            traffic: self.traffic.snapshot(),
        }
    }
}

#[derive(Debug)]
pub struct InstanceStatsAtomic {
    inst: OnceLock<String>,
    started_at: Instant,
    routes_active: AtomicU64,
    sessions_active: AtomicU64,
    traffic: TrafficCountersShared,
}

impl InstanceStatsAtomic {
    fn new() -> Self {
        Self {
            inst: OnceLock::new(),
            started_at: Instant::now(),
            routes_active: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            traffic: TrafficCountersShared::new(),
        }
    }

    pub fn set_instance_name(&self, inst: String) {
        let _ = self.inst.set(inst);
    }

    pub fn record_c2s(&self, bytes: u64, chunks: u64) {
        self.traffic.record_c2s(bytes, chunks);
    }

    pub fn record_s2c(&self, bytes: u64, chunks: u64) {
        self.traffic.record_s2c(bytes, chunks);
    }

    pub fn set_routes_active(&self, total: u64) {
        self.routes_active.store(total, Ordering::Relaxed);
    }

    pub fn set_sessions_active(&self, total: u64) {
        self.sessions_active.store(total, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> InstanceStats {
        InstanceStats {
            inst: self.inst.get().cloned().unwrap_or_else(|| "".to_string()),
            uptime_ms: self.started_at.elapsed().as_millis() as u64,
            routes_active: self.routes_active.load(Ordering::Relaxed),
            sessions_active: self.sessions_active.load(Ordering::Relaxed),
            traffic: self.traffic.snapshot(),
        }
    }
}

impl Default for InstanceStatsAtomic {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SessionInspectState {
    pub id: u64,
    pub zone: u64,
    pub route_id: u64,
    pub hostname: String,
    pub created_at_ms: u64,
    pub last_activity_ms: UnsafeCounterU64,
    pub traffic: TrafficCountersAtomic,
    pub attributes: Arc<RwLock<SessionAttributes>>,
    pub route: Arc<RouteStatsAtomic>,
    pub tenant: Arc<TenantStatsAtomic>,
    pub instance: Arc<InstanceStatsAtomic>,
}

#[derive(Serialize)]
struct SessionInspectReportFormat {
    id: u64,
    zone: u64,
    route_id: u64,
    hostname: String,
    created_at_ms: u64,
    last_activity_ms: u64,
    traffic: TrafficCounters,
}

impl From<&SessionInspectState> for SessionInspectReportFormat {
    fn from(state: &SessionInspectState) -> Self {
        Self {
            id: state.id,
            zone: state.zone,
            route_id: state.route_id,
            hostname: state.hostname.clone(),
            created_at_ms: state.created_at_ms,
            last_activity_ms: state.last_activity_ms.load(),
            traffic: state.traffic.snapshot(),
        }
    }
}

impl Serialize for SessionInspectState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SessionInspectReportFormat::from(self).serialize(serializer)
    }
}

impl SessionInspectState {
    pub fn new(
        id: u64,
        zone: u64,
        route_id: u64,
        hostname: String,
        route: Arc<RouteStatsAtomic>,
        tenant: Arc<TenantStatsAtomic>,
        instance: Arc<InstanceStatsAtomic>,
    ) -> Self {
        let now_ms = instance.started_at.elapsed().as_millis() as u64;
        let state = Self {
            id,
            zone,
            route_id,
            hostname,
            created_at_ms: now_ms,
            last_activity_ms: UnsafeCounterU64::default(),
            traffic: TrafficCountersAtomic::new(),
            attributes: Arc::new(RwLock::new(SessionAttributes::default())),
            route,
            tenant,
            instance,
        };
        state.last_activity_ms.store(now_ms);
        state
    }

    pub fn record_c2s(&self, bytes: u64) {
        self.traffic.record_c2s(bytes);
        self.last_activity_ms
            .store(self.instance.started_at.elapsed().as_millis() as u64);
    }

    pub fn record_s2c(&self, bytes: u64) {
        self.traffic.record_s2c(bytes);
        self.last_activity_ms
            .store(self.instance.started_at.elapsed().as_millis() as u64);
    }

    pub fn session_stats_snapshot(&self) -> SessionStats {
        SessionStats {
            id: self.id,
            zone: self.zone,
            route_id: self.route_id,
            last_activity_ms: self.last_activity_ms.load(),
            traffic: self.traffic.snapshot(),
        }
    }
}

#[derive(Debug)]
pub struct InspectRegistry {
    instance: Arc<InstanceStatsAtomic>,
    routes: RwLock<HashMap<u64, Arc<RouteStatsAtomic>>>,
    tenants: RwLock<HashMap<u64, Arc<TenantStatsAtomic>>>,
    session_cursor: AtomicU64,
}

impl InspectRegistry {
    pub fn new() -> Self {
        Self {
            instance: Arc::new(InstanceStatsAtomic::new()),
            routes: RwLock::new(HashMap::new()),
            tenants: RwLock::new(HashMap::new()),
            session_cursor: AtomicU64::new(1),
        }
    }

    pub fn set_instance_name(&self, inst: String) {
        self.instance.set_instance_name(inst);
    }

    pub fn instance(&self) -> Arc<InstanceStatsAtomic> {
        self.instance.clone()
    }

    pub fn next_session_id(&self) -> u64 {
        self.session_cursor.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn ensure_route(&self, route_id: u64, zone: u64) -> Arc<RouteStatsAtomic> {
        let mut routes = self.routes.write().await;
        let entry = routes
            .entry(route_id)
            .or_insert_with(|| Arc::new(RouteStatsAtomic::new(route_id, zone)));
        entry.set_zone(zone);
        entry.clone()
    }

    pub async fn ensure_tenant(&self, zone: u64) -> Arc<TenantStatsAtomic> {
        let mut tenants = self.tenants.write().await;
        tenants
            .entry(zone)
            .or_insert_with(|| Arc::new(TenantStatsAtomic::new(zone)))
            .clone()
    }

    pub async fn snapshot_routes(&self) -> Vec<RouteStats> {
        let routes = self.routes.read().await;
        routes.values().map(|r| r.snapshot()).collect()
    }

    pub async fn snapshot_tenants(&self) -> Vec<TenantStats> {
        let tenants = self.tenants.read().await;
        tenants.values().map(|t| t.snapshot()).collect()
    }

    pub fn snapshot_instance(&self) -> InstanceStats {
        self.instance.snapshot()
    }
}

pub struct StatsSnapshot {
    pub instance: InstanceStats,
    pub tenants: Vec<TenantStats>,
    pub routes: Vec<RouteStats>,
    pub sessions: Vec<SessionStats>,
}

pub fn inspect_session_to_view(
    session: &super::Session,
    client_addr: String,
    destination_addr: String,
    endpoint_host: String,
    attributes: SessionAttributes,
) -> SessionInspect {
    let state = &session.inspect;
    SessionInspect {
        id: state.id,
        zone: state.zone,
        route_id: state.route_id,
        client_addr,
        destination_addr,
        hostname: state.hostname.clone(),
        endpoint_host,
        created_at_ms: state.created_at_ms,
        last_activity_ms: state.last_activity_ms.load(),
        traffic: state.traffic.snapshot(),
        attributes,
        profile: (*session.profile).clone(),
    }
}
