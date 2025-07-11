use log::info;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{self, Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{self, RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

/// Creates an OpenTelemetry Resource from environment variables following semantic conventions,
/// including OTEL_RESOURCE_ATTRIBUTES for additional key-value pairs.
/// Fallbacks are provided for required attributes like service.name.
pub fn create_resource_from_env() -> Resource {
    let mut attributes = Vec::new();

    // Service attributes
    let service_name =
        env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "unknown-service".to_string());
    attributes.push(KeyValue::new("service.name", service_name));

    if let Ok(service_version) = env::var("OTEL_SERVICE_VERSION") {
        attributes.push(KeyValue::new("service.version", service_version));
    }

    if let Ok(service_namespace) = env::var("OTEL_SERVICE_NAMESPACE") {
        attributes.push(KeyValue::new("service.namespace", service_namespace));
    }

    if let Ok(service_instance_id) = env::var("OTEL_SERVICE_INSTANCE_ID") {
        attributes.push(KeyValue::new("service.instance.id", service_instance_id));
    }

    // Deployment attributes
    if let Ok(deployment_environment) = env::var("OTEL_DEPLOYMENT_ENVIRONMENT") {
        attributes.push(KeyValue::new(
            "deployment.environment",
            deployment_environment,
        ));
    }

    // Parse OTEL_RESOURCE_ATTRIBUTES (comma-separated key=value pairs)
    if let Ok(resource_attributes) = env::var("OTEL_RESOURCE_ATTRIBUTES") {
        let resource_attributes = resource_attributes.clone();
        for kv in resource_attributes.split(',') {
            if let Some((key, value)) = kv.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                if !key.is_empty() && !value.is_empty() {
                    // Skip attributes already set explicitly to avoid duplicates
                    if !attributes.iter().any(|kv| kv.key.as_str() == key) {
                        attributes.push(KeyValue::new(key, value.to_string()));
                    }
                }
            }
        }
    }

    Resource::builder().with_attributes(attributes).build()
}
fn parse_headers() -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    if let Ok(header_str) = dotenvy::var("OTEL_EXPORTER_OTLP_HEADERS") {
        // Expect "key1=val1,key2=val2"
        let header_str = header_str.clone();
        for pair in header_str.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(
                    k.trim().into(),
                    v.trim().parse().expect("Invalid header value"),
                );
            }
        }
    }
    map
}

fn build_span_exporter() -> opentelemetry_otlp::SpanExporter {
    let endpoint = dotenvy::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".into());
    let protocol = dotenvy::var("OTEL_EXPORTER_OTLP_PROTOCOL")
        .unwrap_or_else(|_| "grpc".into())
        .to_lowercase();

    let timeout = dotenvy::var("OTEL_EXPORTER_OTLP_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(3));

    let headers = parse_headers();

    let builder = match protocol.as_str() {
        // "grpc" | "tonic" => {
        //     builder = builder.with_tonic();
        //     builder = builder
        //         .with_endpoint(endpoint)
        //         .with_timeout(timeout)
        //         .with_metadata(headers);
        // }
        "http/protobuf" => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .with_headers(headers),
        "http/json" => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpJson)
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .with_headers(headers),
        other => panic!("Unsupported OTLP_PROTOCOL: {}", other),
    };

    builder.build().expect("failed to build OTLP SpanExporter")
}

fn build_metric_exporter() -> opentelemetry_otlp::MetricExporter {
    let endpoint = dotenvy::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4318/v1/metrics".into());
    let protocol = dotenvy::var("OTEL_EXPORTER_OTLP_PROTOCOL")
        .unwrap_or_else(|_| "grpc".into())
        .to_lowercase();

    info!("Sending metric to {}", endpoint);

    let timeout = dotenvy::var("OTEL_EXPORTER_OTLP_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(3));

    let headers = parse_headers();

    let builder = match protocol.as_str() {
        // "grpc" | "tonic" => {
        //     builder = builder.with_tonic();
        //     builder = builder
        //         .with_endpoint(endpoint)
        //         .with_timeout(timeout)
        //         .with_metadata(headers);
        // }
        "http/protobuf" => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .with_headers(headers),
        "http/json" => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .with_headers(headers),
        other => panic!("Unsupported OTLP_PROTOCOL: {}", other),
    };

    builder
        .build()
        .expect("failed to build OTLP MetricExporter")
}

pub fn init_tracer() -> SdkTracerProvider {
    // Common resource, includes service.name and anything else
    let resource = create_resource_from_env();

    let span_exporter = build_span_exporter();

    // Configure the tracer provider with batch exporter
    let tracer_provider = trace::SdkTracerProvider::builder()
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_max_events_per_span(
            dotenvy::var("OTEL_SPAN_MAX_EVENTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64),
        )
        .with_max_attributes_per_span(
            dotenvy::var("OTEL_SPAN_MAX_ATTRIBUTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(16),
        )
        .with_batch_exporter(span_exporter)
        .with_resource(resource)
        .build();

    global::set_tracer_provider(tracer_provider.clone());
    tracer_provider
}

pub fn init_meter() -> SdkMeterProvider {
    let metric_exporter = build_metric_exporter();
    let resource = create_resource_from_env();

    let meter_provider = SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource);
    
    #[cfg(feature = "verbose")]
    {
        meter_provider = meter_provider.with_periodic_exporter(opentelemetry_stdout::MetricExporter::builder().build());
    }

    let meter_provider = meter_provider.build();
    global::set_meter_provider(meter_provider.clone());
    meter_provider
}
