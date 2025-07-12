pub mod ratelimit;

use crate::threat::ratelimit::RateLimitResult;
use anyhow::bail;
use std::fmt::Display;
use std::future::IntoFuture;
use std::time::Duration;
use tokio::time::timeout;

pub enum ClientIntent {
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

struct Intent {
    label: &'static str,
    expected: Option<Duration>,
}

#[derive(Debug)]
pub struct ThreatControlService;

impl ThreatControlService {
    pub fn new() -> Self {
        Self {}
    }
    /// A `timeout` wrapper with actual determination clause of failure. To control, report and handle
    pub async fn nuisance<F>(
        &self,
        duration: Duration,
        future: F,
        intent: ClientIntent,
    ) -> anyhow::Result<F::Output>
    where
        F: IntoFuture,
    {
        match timeout(duration, future.into_future()).await {
            Ok(v) => Ok(v),
            Err(_) => Err(ClientFail::Timeout.into()),
        }
    }
}
