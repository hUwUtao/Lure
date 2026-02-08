pub mod ratelimit;

use std::{future::IntoFuture, time::Duration};

use log::warn;
use tokio::time::{error::Elapsed, timeout};

use crate::threat::ratelimit::RateLimitResult;

#[derive(Debug)]
pub enum IntentTag {
    Handshake,
    Query,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientFail {
    #[error("Timeout (cf::nt:{elapsed:?})")]
    Timeout {
        intent: ClientIntent,
        elapsed: Elapsed,
    },
    #[error("Rate limited (cf::rl)")]
    RateLimited(RateLimitResult),
}

#[derive(Debug)]
pub struct ClientIntent {
    pub tag: IntentTag,
    pub duration: Duration,
}

#[derive(Debug)]
pub struct ThreatControlService;

impl Default for ThreatControlService {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatControlService {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
    /// A `timeout` wrapper with actual determination clause of failure. To control, report and handle
    pub async fn nuisance<F>(&self, future: F, intent: ClientIntent) -> anyhow::Result<F::Output>
    where
        F: IntoFuture,
    {
        match timeout(intent.duration, future.into_future()).await {
            Ok(v) => Ok(v),
            Err(elapsed) => {
                warn!(
                    "Client {:?} timed out after {:?}",
                    intent.tag, intent.duration
                );
                Err(ClientFail::Timeout { intent, elapsed }.into())
            }
        }
    }
}
