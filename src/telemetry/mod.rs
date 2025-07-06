pub mod event;

use crate::lure::EventIdent;
use crate::router::RouteReport;
use crate::telemetry::event::EventService;
use opentelemetry::global;
use opentelemetry::metrics::Meter;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

pub fn init_meter_provider(url: String) -> anyhow::Result<SdkMeterProvider> {
    // let logged = opentelemetry_stdout::MetricExporterBuilder::default().build();
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(url)
        .build()?;
    let provider = SdkMeterProvider::builder()
        // .with_periodic_exporter(logged)
        .with_periodic_exporter(exporter)
        .with_resource(Resource::builder().with_service_name("alureproxy").build())
        .build();
    global::set_meter_provider(provider.clone());
    Ok(provider)
}

pub fn get_meter() -> Meter {
    global::meter("alure")
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
