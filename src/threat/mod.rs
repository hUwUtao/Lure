pub mod ratelimit;

use anyhow::bail;
use std::fmt::Display;
use std::future::IntoFuture;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum ClientIntent {
    Handshake,
    Query,
    Login,
    Transport,
}

impl Display for ClientIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

struct Intent {
    label: &'static str,
    expected: Option<Duration>,
}

struct ThreatControlService;

impl ThreatControlService {
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
            Err(_) => {
                bail!("nuisance check timeout");
            }
        }
    }
}
