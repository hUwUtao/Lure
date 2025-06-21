use opentelemetry::global;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;
pub fn init_meter_provider() -> anyhow::Result<SdkMeterProvider> {
    let logged = opentelemetry_stdout::MetricExporterBuilder::default().build();
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint("http://10.1.0.3:9091/api/v1/otlp/v1/metrics")
        .build()?;
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(logged)
        .with_periodic_exporter(exporter)
        .with_resource(Resource::builder().with_service_name("alureproxy").build())
        .build();
    global::set_meter_provider(provider.clone());
    Ok(provider)
}
