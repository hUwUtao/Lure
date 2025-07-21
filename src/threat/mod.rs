pub mod ratelimit;

use std::{future::IntoFuture, time::Duration};

use tokio::time::timeout;

use crate::threat::ratelimit::RateLimitResult;

pub enum IntentTag {
    Handshake,
    Query,
    Login,
    Transport,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientFail {
    #[error("Timeout (cf::nt)")]
    Timeout,
    #[error("Rate limited (cf::rl)")]
    RateLimited(RateLimitResult),
}

pub struct ClientIntent {
    pub tag: IntentTag,
    pub duration: Duration,
}

#[derive(Debug)]
pub struct ThreatControlService;

impl ThreatControlService {
    pub fn new() -> Self {
        Self {}
    }
    /// A `timeout` wrapper with actual determination clause of failure. To control, report and handle
    pub async fn nuisance<F>(&self, future: F, intent: ClientIntent) -> anyhow::Result<F::Output>
    where
        F: IntoFuture,
    {
        match timeout(intent.duration, future.into_future()).await {
            Ok(v) => Ok(v),
            Err(_) => Err(ClientFail::Timeout.into()),
        }
    }
}
