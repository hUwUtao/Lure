pub mod event;
pub mod inspect;
pub mod oltp;
pub mod process;

use std::{sync::Arc, time::Duration};

use opentelemetry::{global, global::BoxedTracer, metrics::Meter, trace::TracerProvider};
use serde::{Deserialize, Serialize};

use crate::{
    lure::EventIdent,
    router::RouteReport,
    telemetry::{
        event::EventService,
        inspect::{InspectRequest, ListSessionsResponse, ListStatsResponse},
    },
};

pub fn get_meter() -> Meter {
    global::meter_provider().meter("alure")
}
pub fn get_tracer() -> BoxedTracer {
    global::tracer_provider().tracer("alure")
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Id {
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Empty {}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct NonObj<T> {
    _v: T,
}

impl<T> NonObj<T> {
    pub fn new(v: T) -> Self {
        Self { _v: v }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "_c")]
pub(crate) enum EventEnvelope {
    Hello(Empty),
    SetRoute(crate::router::Route),
    RemoveRoute(Id),
    FlushTunnelTokens(Empty),
    SetTunnelToken(crate::config::TokenEntry),
    ListRouteRequest(Empty),
    ListRouteResponse(NonObj<Vec<crate::router::Route>>),
    ListSessionsRequest(InspectRequest),
    ListSessionsResponse(ListSessionsResponse),
    ListStatsRequest(InspectRequest),
    ListStatsResponse(ListStatsResponse),
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
