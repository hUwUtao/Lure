use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InspectRequest {
    pub req: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TrafficCounters {
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
    pub c2s_chunks: u64,
    pub s2c_chunks: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SessionAttributes {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionInspect {
    pub id: u64,
    pub zone: u64,
    pub route_id: u64,
    pub client_addr: String,
    pub destination_addr: String,
    pub hostname: String,
    pub endpoint_host: String,
    pub created_at_ms: u64,
    pub last_activity_ms: u64,
    pub traffic: TrafficCounters,
    pub attributes: SessionAttributes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListSessionsResponse {
    pub req: u64,
    pub _v: Vec<SessionInspect>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstanceStats {
    pub inst: String,
    pub uptime_ms: u64,
    pub routes_active: u64,
    pub sessions_active: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RouteStats {
    pub id: u64,
    pub zone: u64,
    pub active_sessions: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TenantStats {
    pub zone: u64,
    pub active_sessions: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionStats {
    pub id: u64,
    pub zone: u64,
    pub route_id: u64,
    pub last_activity_ms: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListStatsResponse {
    pub req: u64,
    pub instance: InstanceStats,
    pub tenants: Vec<TenantStats>,
    pub routes: Vec<RouteStats>,
    pub sessions: Vec<SessionStats>,
}
