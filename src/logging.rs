use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Error;
use log::{debug, error, info, warn};

pub struct LureLogger;

impl LureLogger {
    pub fn preparing_socket(address: &str) {
        info!("Preparing socket {}", address);
    }

    pub fn rate_limited(ip: &IpAddr) {
        debug!("Rate-limited {ip}");
    }

    pub fn tcp_nodelay_failed(err: &std::io::Error) {
        error!("Failed to set TCP_NODELAY: {err}");
    }

    pub fn new_connection(address: &SocketAddr) {
        info!("New connection {}", address);
    }

    pub fn handshake_completed(elapsed_ms: u64, next_state: &str) {
        debug!(
            "Handshake completed in {}ms, next state: {}",
            elapsed_ms, next_state
        );
    }

    pub fn connection_closed(addr: &SocketAddr, err: &Error) {
        debug!("Connection {addr} closed: {err}");
    }

    pub fn connection_error(client: &SocketAddr, server: Option<&SocketAddr>, err: &dyn Display) {
        if dotenvy::var("DO_NOT_LOG_CONNECTION_ERROR").is_ok() {
            return;
        }
        let server_str = server.map(|s| format!(" -> {s}")).unwrap_or_default();
        error!("connection error@{client}{server_str}: {}", err);
    }

    pub fn disconnect_warning(addr: &SocketAddr, reason: &str) {
        warn!("Disconnecting client {addr}: {reason}");
    }

    pub fn disconnect_failure(addr: &SocketAddr, err: &Error) {
        debug!("Failed to send disconnect to {addr}: {err}");
    }

    pub fn session_creation_failed(addr: &SocketAddr, hostname: &str, err: &Error) {
        debug!("Failed to create session for {addr} (host '{hostname}'): {err}");
    }

    pub fn session_creation_timeout(addr: &SocketAddr, hostname: &str) {
        debug!("Session creation timed out for {addr} (host '{hostname}')");
    }

    pub fn parser_failure(addr: &SocketAddr, stage: &str, err: &Error) {
        warn!("Parser failed during {stage} for client {addr}: {err}");
    }

    pub fn backend_failure(
        client: Option<&SocketAddr>,
        backend: SocketAddr,
        stage: &str,
        err: &Error,
    ) {
        match client {
            Some(addr) => error!("Backend {stage} failed for client {addr} -> {backend}: {err}"),
            None => error!("Backend {stage} failed for {backend}: {err}"),
        }
    }

    pub fn deadline_missed(
        stage: &str,
        duration: Duration,
        client: Option<&SocketAddr>,
        target: Option<&str>,
    ) {
        let mut context = String::new();
        if let Some(addr) = client {
            context.push_str(&format!(" client={addr}"));
        }
        if let Some(t) = target {
            context.push_str(&format!(" target={t}"));
        }
        warn!(
            "Deadline exceeded while {stage} (limit {:?}){}",
            duration, context
        );
    }
}
