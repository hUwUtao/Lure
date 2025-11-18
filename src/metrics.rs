use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge, Histogram, Meter},
};

pub struct HandshakeMetrics {
    open: Counter<u64>,
    attempts: Counter<u64>,
    failures: Counter<u64>,
    duration: Histogram<u64>,
}

impl HandshakeMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            open: meter.u64_counter("lure_socket_open_total").build(),
            attempts: meter.u64_counter("lure_handshake_total").build(),
            failures: meter.u64_counter("lure_handshake_fail_total").build(),
            duration: meter.u64_histogram("lure_handshake_time_ms").build(),
        }
    }

    pub fn record_open(&self) {
        self.open.add(1, &[]);
    }

    pub fn record_attempt(&self, state: &str) {
        self.attempts
            .add(1, &[KeyValue::new("state", state.to_string())]);
    }

    pub fn record_failure(&self, state: &str) {
        self.failures
            .add(1, &[KeyValue::new("state", state.to_string())]);
    }

    pub fn record_duration(&self, elapsed_ms: u64, state: &str) {
        self.duration
            .record(elapsed_ms, &[KeyValue::new("state", state.to_string())]);
    }
}

#[derive(Debug)]
pub struct RouterMetrics {
    routes_active: Gauge<u64>,
    routes_resolve: Counter<u64>,
    sessions_active: Gauge<u64>,
    session_create: Counter<u64>,
    session_destroy: Counter<u64>,
}

impl RouterMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            routes_active: meter.u64_gauge("lure_router_routes_active").build(),
            routes_resolve: meter.u64_counter("lure_router_routes_resolve").build(),
            sessions_active: meter.u64_gauge("lure_router_sessions_active").build(),
            session_create: meter.u64_counter("lure_router_session_create").build(),
            session_destroy: meter.u64_counter("lure_router_session_destroy").build(),
        }
    }

    pub fn record_routes_active(&self, total: u64) {
        self.routes_active.record(total, &[]);
    }

    pub fn record_routes_resolve(&self) {
        self.routes_resolve.add(1, &[]);
    }

    pub fn record_sessions_active(&self, total: u64) {
        self.sessions_active.record(total, &[]);
    }

    pub fn record_session_create(&self) {
        self.session_create.add(1, &[]);
    }

    pub fn record_session_destroy(&self) {
        self.session_destroy.add(1, &[]);
    }
}
