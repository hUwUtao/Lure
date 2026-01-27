use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use opentelemetry::metrics::Counter;
use opentelemetry::KeyValue;

use crate::{
    telemetry::get_meter,
    router::RouterInstance,
    router::inspect::SessionInspectState,
    telemetry::{
        EventEnvelope, EventServiceInstance,
        event::EventHook,
        inspect::{InspectRequest, ListSessionsResponse, ListStatsResponse},
    },
};

pub(crate) fn transport_volume_counter() -> Counter<u64> {
    get_meter()
        .u64_counter("lure_proxy_transport_volume")
        .with_unit("bytes")
        .build()
}

pub(crate) fn transport_packet_counter() -> Counter<u64> {
    get_meter()
        .u64_counter("lure_proxy_transport_packet_count")
        .with_unit("packets")
        .build()
}

pub(crate) fn transport_counters() -> (Counter<u64>, Counter<u64>) {
    (transport_volume_counter(), transport_packet_counter())
}

pub(crate) async fn drive_transport_metrics<F>(
    inspect: Arc<SessionInspectState>,
    mut should_stop: F,
) where
    F: FnMut() -> bool,
{
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    let (volume_record, packet_record) = transport_counters();

    let s2ct = KeyValue::new("intent", "s2c");
    let c2st = KeyValue::new("intent", "c2s");

    let mut last = inspect.traffic.snapshot();

    loop {
        if should_stop() {
            break;
        }

        let snap = inspect.traffic.snapshot();

        let delta_c2s_bytes = snap.c2s_bytes - last.c2s_bytes;
        let delta_s2c_bytes = snap.s2c_bytes - last.s2c_bytes;
        let delta_c2s_chunks = snap.c2s_chunks - last.c2s_chunks;
        let delta_s2c_chunks = snap.s2c_chunks - last.s2c_chunks;

        volume_record.add(delta_c2s_bytes, core::slice::from_ref(&c2st));
        volume_record.add(delta_s2c_bytes, core::slice::from_ref(&s2ct));
        packet_record.add(delta_c2s_chunks, core::slice::from_ref(&c2st));
        packet_record.add(delta_s2c_chunks, core::slice::from_ref(&s2ct));

        inspect
            .route
            .record_c2s(delta_c2s_bytes, delta_c2s_chunks);
        inspect
            .route
            .record_s2c(delta_s2c_bytes, delta_s2c_chunks);
        inspect
            .tenant
            .record_c2s(delta_c2s_bytes, delta_c2s_chunks);
        inspect
            .tenant
            .record_s2c(delta_s2c_bytes, delta_s2c_chunks);
        inspect
            .instance
            .record_c2s(delta_c2s_bytes, delta_c2s_chunks);
        inspect
            .instance
            .record_s2c(delta_s2c_bytes, delta_s2c_chunks);

        last = snap;

        interval.tick().await;
    }
}

pub(crate) struct InspectHook {
    router: &'static RouterInstance,
}

impl InspectHook {
    pub(crate) fn new(router: &'static RouterInstance) -> Self {
        Self { router }
    }

    async fn handle_list_sessions(
        &self,
        service: &EventServiceInstance,
        req: &InspectRequest,
    ) -> anyhow::Result<()> {
        let sessions = self.router.inspect_sessions().await;
        service
            .produce_event(EventEnvelope::ListSessionsResponse(ListSessionsResponse {
                req: req.req,
                _v: sessions,
            }))
            .await?;
        Ok(())
    }

    async fn handle_list_stats(
        &self,
        service: &EventServiceInstance,
        req: &InspectRequest,
    ) -> anyhow::Result<()> {
        let stats = self.router.inspect_stats().await;
        service
            .produce_event(EventEnvelope::ListStatsResponse(ListStatsResponse {
                req: req.req,
                instance: stats.instance,
                tenants: stats.tenants,
                routes: stats.routes,
                sessions: stats.sessions,
            }))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl EventHook<EventEnvelope, EventEnvelope> for InspectHook {
    async fn on_event(
        &self,
        service: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        match event {
            EventEnvelope::ListSessionsRequest(req) => {
                self.handle_list_sessions(service, req).await
            }
            EventEnvelope::ListStatsRequest(req) => self.handle_list_stats(service, req).await,
            _ => Ok(()),
        }
    }
}
