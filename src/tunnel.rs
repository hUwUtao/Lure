use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Context;
use async_trait::async_trait;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::{
    sync::{RwLock, mpsc, mpsc::UnboundedSender, oneshot},
    time::Duration,
};

use crate::{
    config::TokenEntry,
    logging::LureLogger,
    router::AuthMode,
    sock::LureConnection,
    telemetry::{EventEnvelope, EventServiceInstance},
    utils::spawn_named,
};

#[derive(Debug)]
pub enum TunnelControlMsg {
    Flush,
    Upsert(TokenEntry),
}

pub struct TunnelControlHook {
    tx: UnboundedSender<TunnelControlMsg>,
}

impl TunnelControlHook {
    pub fn new(tx: UnboundedSender<TunnelControlMsg>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl crate::telemetry::event::EventHook<EventEnvelope, EventEnvelope> for TunnelControlHook {
    async fn on_event(
        &self,
        _: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        match event {
            EventEnvelope::FlushTunnelTokens(_) => {
                log::info!("tunnel: flush token registry (control-plane)");
                let _ = self.tx.send(TunnelControlMsg::Flush);
            }
            EventEnvelope::SetTunnelToken(entry) => {
                log::info!(
                    "tunnel: upsert token (control-plane): key_id={} zone={:?} name={:?}",
                    entry.key_id,
                    entry.zone,
                    entry.name
                );
                let _ = self.tx.send(TunnelControlMsg::Upsert(entry.clone()));
            }
            _ => {}
        }
        Ok(())
    }
}

fn key_id_prefix(key_id: &[u8; 8]) -> String {
    format!("{:02x}", key_id[0])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TokenKeyId(pub [u8; 8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionToken(pub [u8; 32]);

pub struct TokenInfo {
    /// Full 32-byte secret for HMAC
    pub secret: [u8; 32],
    /// Optional human-readable name
    pub name: Option<String>,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last authentication timestamp
    pub last_used: RwLock<Instant>,
}

pub struct TunnelRegistry {
    /// Token registry by key_id
    tokens: RwLock<HashMap<TokenKeyId, Arc<TokenInfo>>>,
    /// Optional mapping from zone -> key_id (set when token entries include zone).
    zones: RwLock<HashMap<u64, TokenKeyId>>,
    /// Active agents by key_id
    agents: RwLock<HashMap<TokenKeyId, AgentRecord>>,
    /// Monotonic id for per-key agent generations.
    agent_gen: std::sync::atomic::AtomicU64,
    /// Pending sessions
    pending: RwLock<HashMap<SessionToken, PendingSession>>,
    /// Expired sessions counter
    expired_sessions: std::sync::atomic::AtomicU64,
}

struct AgentRecord {
    id: u64,
    tx: mpsc::Sender<TunnelCommand>,
    task: tokio::task::JoinHandle<()>,
}

struct PendingSession {
    key_id: TokenKeyId,
    target: SocketAddr,
    respond: oneshot::Sender<LureConnection>,
    created_at: Instant,
}

enum TunnelCommand {
    OfferSession { session: SessionToken },
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            zones: RwLock::new(HashMap::new()),
            agents: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            expired_sessions: std::sync::atomic::AtomicU64::new(0),
            agent_gen: std::sync::atomic::AtomicU64::new(1),
        }
    }
}

impl TunnelRegistry {
    /// Load tokens from configuration
    pub async fn load_tokens(&self, config: &crate::config::TunnelConfig) -> anyhow::Result<()> {
        let mut tokens = self.tokens.write().await;
        let mut zones = self.zones.write().await;
        tokens.clear();
        zones.clear();

        for entry in &config.token {
            let key_id = parse_key_id(&entry.key_id).context("parsing key_id")?;
            let secret = parse_secret(&entry.secret).context("parsing secret")?;

            let token_key = TokenKeyId(key_id);
            if let Some(zone) = entry.zone {
                zones.insert(zone, token_key);
            }

            tokens.insert(
                token_key,
                Arc::new(TokenInfo {
                    secret,
                    name: entry.name.clone(),
                    created_at: Instant::now(),
                    last_used: RwLock::new(Instant::now()),
                }),
            );
        }

        log::info!("tunnel: loaded {} tokens (settings.toml)", tokens.len());
        Ok(())
    }

    /// Clear only the token registry (and pending sessions).
    ///
    /// Agents are not disconnected/cleared here: agents register directly with Lure,
    /// and a control-plane resync should not kick them out. If a token is removed,
    /// offers will fail because the key_id is no longer present.
    pub async fn clear_runtime(&self) {
        {
            let mut tokens = self.tokens.write().await;
            tokens.clear();
        }
        {
            let mut zones = self.zones.write().await;
            zones.clear();
        }
        {
            let mut pending = self.pending.write().await;
            pending.clear();
        }
        log::info!("tunnel: cleared runtime token/zone/pending state");
    }

    pub async fn upsert_token(&self, entry: &TokenEntry) -> anyhow::Result<()> {
        let key_id = parse_key_id(&entry.key_id).context("parsing key_id")?;
        let secret = parse_secret(&entry.secret).context("parsing secret")?;

        let token_key = TokenKeyId(key_id);

        let mut tokens = self.tokens.write().await;
        let mut zones = self.zones.write().await;
        if let Some(zone) = entry.zone {
            zones.insert(zone, token_key);
        }
        tokens.insert(
            token_key,
            Arc::new(TokenInfo {
                secret,
                name: entry.name.clone(),
                created_at: Instant::now(),
                last_used: RwLock::new(Instant::now()),
            }),
        );
        log::info!(
            "tunnel: token upserted: key_id={} zone={:?} name={:?} (total={})",
            entry.key_id,
            entry.zone,
            entry.name,
            tokens.len()
        );
        Ok(())
    }

    pub async fn key_id_for_zone(&self, zone: u64) -> Option<TokenKeyId> {
        self.zones.read().await.get(&zone).copied()
    }

    /// Validate HMAC authentication
    async fn validate_hmac(
        &self,
        key_id: &TokenKeyId,
        timestamp: u64,
        intent: tun::Intent,
        session: Option<&[u8; 32]>,
        provided_hmac: &[u8; 32],
    ) -> anyhow::Result<Arc<TokenInfo>> {
        // Check timestamp is within a small window for replay protection.
        //
        // In practice, production boxes (or containers) can drift a bit; keep this tolerant enough
        // to avoid flapping when NTP isn't perfect.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if now.abs_diff(timestamp) > 60 {
            anyhow::bail!("timestamp out of range (replay protection failed)");
        }

        // Look up token
        let token_info = self
            .tokens
            .read()
            .await
            .get(key_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("invalid key_id"))?;

        // Compute expected HMAC
        let expected_hmac =
            tun::compute_agent_hmac(&token_info.secret, &key_id.0, timestamp, intent, session);

        // Constant-time comparison to prevent timing attacks
        let choice: subtle::Choice = provided_hmac.ct_eq(&expected_hmac);
        if !bool::from(choice) {
            anyhow::bail!("HMAC validation failed");
        }

        // Update last_used
        *token_info.last_used.write().await = Instant::now();
        Ok(token_info)
    }

    pub async fn register_listener(
        self: &Arc<Self>,
        key_id: TokenKeyId,
        timestamp: u64,
        hmac: [u8; 32],
        mut connection: LureConnection,
    ) -> anyhow::Result<()> {
        // Validate HMAC
        let _token_info = self
            .validate_hmac(&key_id, timestamp, tun::Intent::Listen, None, &hmac)
            .await?;

        let (tx, mut rx) = mpsc::channel(8);
        let id = self
            .agent_gen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        LureLogger::tunnel_agent_registered(&key_id_prefix(&key_id.0));

        // Spawn the task that will push offers to the agent. If a new agent registers with the
        // same key_id (restart), we abort the old task and replace it.
        let registry = Arc::clone(self);
        let task = spawn_named("tunnel-agent-listener", async move {
            while let Some(cmd) = rx.recv().await {
                let mut buf = Vec::new();
                match cmd {
                    TunnelCommand::OfferSession { session } => {
                        tun::encode_server_msg(&tun::ServerMsg::SessionOffer(session.0), &mut buf);
                    }
                }
                if connection.write_all(buf).await.is_err() {
                    break;
                }
            }
            let mut agents = registry.agents.write().await;
            if let Some(active) = agents.get(&key_id) {
                if active.id == id {
                    agents.remove(&key_id);
                }
            }
            LureLogger::tunnel_agent_disconnected(&key_id_prefix(&key_id.0));
        })
        .context("failed to spawn tunnel listener task")?;

        // Replace any existing registration for this key_id (common on agent restart).
        {
            let mut agents = self.agents.write().await;
            if let Some(old) = agents.remove(&key_id) {
                old.task.abort();
            }
            agents.insert(
                key_id,
                AgentRecord {
                    id,
                    tx: tx.clone(),
                    task,
                },
            );
        }

        Ok(())
    }

    pub async fn offer_session(
        &self,
        key_id: TokenKeyId,
        session: SessionToken,
        target: SocketAddr,
        auth_mode: &AuthMode,
    ) -> anyhow::Result<oneshot::Receiver<LureConnection>> {
        // If the key_id isn't currently registered, don't offer a session (prevents
        // offering to stale/removed tokens and avoids pending-session leaks).
        {
            let tokens = self.tokens.read().await;
            if !tokens.contains_key(&key_id) {
                anyhow::bail!("tunnel token not registered for key_id");
            }
        }

        // Check if this key_id is authorized for this route
        match auth_mode {
            AuthMode::Public => {
                // Public routes don't use tunnel auth
                anyhow::bail!("public routes require different handling");
            }
            AuthMode::Protected => {
                // Any valid token (already validated) can access
            }
            AuthMode::Restricted { allowed_tokens } => {
                // Only specific tokens allowed
                if !allowed_tokens.contains(&key_id.0) {
                    anyhow::bail!("key_id not authorized for this route (restricted auth_mode)");
                }
            }
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.write().await;
            pending.insert(
                session,
                PendingSession {
                    key_id,
                    target,
                    respond: tx,
                    created_at: Instant::now(),
                },
            );
        }

        LureLogger::tunnel_session_offered(&key_id_prefix(&key_id.0), &target);

        let agent_tx = { self.agents.read().await.get(&key_id).map(|a| a.tx.clone()) };
        let Some(agent_tx) = agent_tx else {
            let mut pending = self.pending.write().await;
            pending.remove(&session);
            LureLogger::tunnel_agent_missing(
                &key_id_prefix(&key_id.0),
                &format!("{:02x}", session.0[0]),
            );
            anyhow::bail!("no active tunnel agent registered for key_id");
        };

        match agent_tx.send(TunnelCommand::OfferSession { session }).await {
            Ok(()) => Ok(rx),
            Err(_) => {
                let mut pending = self.pending.write().await;
                pending.remove(&session);
                LureLogger::tunnel_agent_missing(
                    &key_id_prefix(&key_id.0),
                    &format!("{:02x}", session.0[0]),
                );
                anyhow::bail!("failed to notify tunnel agent")
            }
        }
    }

    pub async fn accept_connect(
        &self,
        key_id: TokenKeyId,
        timestamp: u64,
        hmac: [u8; 32],
        session: SessionToken,
        mut connection: LureConnection,
    ) -> anyhow::Result<()> {
        // Validate HMAC with session
        self.validate_hmac(
            &key_id,
            timestamp,
            tun::Intent::Connect,
            Some(&session.0),
            &hmac,
        )
        .await?;

        let pending = {
            let mut pending = self.pending.write().await;
            pending.remove(&session)
        };
        let Some(pending) = pending else {
            LureLogger::tunnel_session_missing(&format!("{:02x}", session.0[0]));
            anyhow::bail!("no pending tunnel session");
        };

        // Validate that the provided key_id matches the one that created this session
        if pending.key_id != key_id {
            LureLogger::tunnel_token_mismatch(
                &key_id_prefix(&key_id.0),
                &format!("{:02x}", session.0[0]),
            );
            anyhow::bail!("key_id mismatch: unauthorized accept attempt");
        }

        LureLogger::tunnel_session_accepted(&key_id_prefix(&key_id.0), &pending.target);

        let mut buf = Vec::new();
        tun::encode_server_msg(&tun::ServerMsg::TargetAddr(pending.target), &mut buf);
        connection
            .write_all(buf)
            .await
            .context("failed to send tunnel target")?;

        pending
            .respond
            .send(connection)
            .map_err(|_| anyhow::anyhow!("pending tunnel session closed"))?;

        let agents = self.agents.read().await;
        if !agents.contains_key(&key_id) {
            // Agent may not be registered anymore; best-effort only.
        }

        Ok(())
    }

    pub(crate) async fn cleanup_expired_sessions(&self) {
        const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

        let mut pending = self.pending.write().await;
        let now = Instant::now();
        let expired: Vec<_> = pending
            .iter()
            .filter(|(_, session)| now.duration_since(session.created_at) > SESSION_TIMEOUT)
            .map(|(token, _)| *token)
            .collect();

        for token in expired {
            pending.remove(&token);
            self.expired_sessions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Tunnel session expired: {:?}", token.0[..8].to_vec());
        }
    }
}

fn parse_key_id(key_id_str: &str) -> anyhow::Result<[u8; 8]> {
    let trimmed = key_id_str.trim();
    if trimmed.len() != 16 {
        anyhow::bail!("key_id must be 16 hex characters, got {}", trimmed.len());
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("key_id must be hex-encoded");
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
        out[i] = byte;
    }
    Ok(out)
}

fn parse_secret(secret_str: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = secret_str.trim();
    // Try hex first
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
            out[i] = byte;
        }
        return Ok(out);
    }
    // Try base64
    use base64::{Engine, engine::general_purpose::STANDARD};
    let decoded = STANDARD.decode(trimmed)?;
    if decoded.len() != 32 {
        anyhow::bail!(
            "secret must be 64-char hex or valid base64 for 32 bytes, got {}",
            decoded.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zone_mapping_is_updated_on_upsert_and_cleared() {
        let registry = TunnelRegistry::default();
        let entry = TokenEntry {
            key_id: "0011223344556677".to_string(),
            secret: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            name: None,
            zone: Some(42),
        };

        registry.upsert_token(&entry).await.unwrap();

        let key = registry.key_id_for_zone(42).await.unwrap();
        assert_eq!(key.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        registry.clear_runtime().await;
        assert!(registry.key_id_for_zone(42).await.is_none());
    }
}
