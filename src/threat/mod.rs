pub mod ratelimit;

use crate::threat::ratelimit::RateLimitResult;
use anyhow::bail;
use std::fmt::Display;
use std::future::IntoFuture;
use std::time::Duration;
use tokio::time::timeout;

pub enum IntentTag {
    Handshake,
    Query,
    Login,
    Transport,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientFail {
    #[error("Timeout")]
    Timeout,
    #[error("Rate limited")]
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
