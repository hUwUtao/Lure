pub mod event;
pub(crate) mod oltp;

use crate::lure::EventIdent;
use crate::router::RouteReport;
use crate::telemetry::event::EventService;
use opentelemetry::global;
use opentelemetry::global::BoxedTracer;
use opentelemetry::metrics::Meter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use opentelemetry::trace::TracerProvider;

/// Initializes an OTLP TracerProvider, optionally using gRPC via `--features grpc-tonic`.

pub fn get_meter() -> Meter {
    global::meter_provider().meter("alure")
}
pub fn get_tracer() -> BoxedTracer {
    global::tracer_provider().tracer("alure")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Id {
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Empty {}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonObj<T> {
    _v: T,
}

impl<T> NonObj<T> {
    pub fn new(v: T) -> Self {
        Self { _v: v }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "_c")]
pub enum EventEnvelope {
    Hello(Empty),
    SetRoute(crate::router::Route),
    RemoveRoute(Id),
    ListRouteRequest(Empty),
    ListRouteResponse(NonObj<Vec<crate::router::Route>>),
    FlushRoute(Empty),
    HandshakeRoute(RouteReport),
    HandshakeIdent(EventIdent),
}

pub type EventServiceInstance = Arc<EventService<EventEnvelope, EventEnvelope>>;

pub(crate) fn init_event(url: String) -> Arc<EventService<EventEnvelope, EventEnvelope>> {
    let service: EventService<EventEnvelope, EventEnvelope> =
        EventService::new(url, Duration::from_secs(1));

    Arc::new(service)
}
