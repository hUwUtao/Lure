use std::net::SocketAddr;

use anyhow::Result;
use valence_text::{Color, IntoText};

use crate::{connection::EncodedConnection, logging::LureLogger, threat::ClientFail};

#[derive(thiserror::Error, Debug)]
pub enum ReportableError {
    #[error("Request timeout (re::rt)")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Networking error - {0:?} (re:ne)")]
    IoError(#[from] tokio::io::Error),
    #[error("Bad request (re::br)")]
    ClientError(#[from] ClientFail),
    #[error("Unknown error (re::??)")]
    Anyhow(#[from] anyhow::Error),
}

#[derive(Clone, Copy, Default)]
pub struct ErrorResponder;

impl ErrorResponder {
    pub const fn new() -> Self {
        Self
    }

    pub async fn disconnect_with_log<S, L>(
        &self,
        client: &mut EncodedConnection<'_>,
        addr: SocketAddr,
        public_reason: S,
        log_reason: L,
    ) -> Result<()>
    where
        S: Into<String>,
        L: Into<String>,
    {
        let public_reason = public_reason.into();
        let log_reason = log_reason.into();
        LureLogger::disconnect_warning(&addr, &log_reason);
        client
            .disconnect_player(public_reason.into_text().color(Color::RED))
            .await
    }

    pub async fn disconnect_with_error(
        &self,
        client: &mut EncodedConnection<'_>,
        addr: SocketAddr,
        err: &ReportableError,
        context: impl Into<String>,
    ) -> Result<()> {
        let context = context.into();
        let err_msg = err.to_string();
        let public_reason = format!("Gateway error:\n\n{}", err_msg);
        let log_reason = format!("{}: {}", context, err_msg);
        self.disconnect_with_log(client, addr, public_reason, log_reason)
            .await
    }
}
