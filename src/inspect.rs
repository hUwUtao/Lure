use async_trait::async_trait;

use crate::{
    router::RouterInstance,
    telemetry::{
        EventEnvelope, EventServiceInstance,
        event::EventHook,
        inspect::{InspectRequest, ListSessionsResponse, ListStatsResponse},
    },
};

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
            EventEnvelope::ListSessionsRequest(req) => self.handle_list_sessions(service, req).await,
            EventEnvelope::ListStatsRequest(req) => self.handle_list_stats(service, req).await,
            _ => Ok(()),
        }
    }
}

