use anyhow::bail;
use std::future::IntoFuture;
use std::time::Duration;
use tokio::time::timeout;

pub enum ClientIntent {
    Handshake,
    Query,
    Login,
    Transport,
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
