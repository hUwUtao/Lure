use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Context;
use log::debug;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::Duration;

use crate::{logging::LureLogger, sock::LureConnection, utils::spawn_named};

fn token_prefix(token: &[u8; 32]) -> String {
    format!("{:02x}", token[0])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TunnelToken(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionToken(pub [u8; 32]);

pub struct TunnelRegistry {
    agents: RwLock<HashMap<TunnelToken, AgentHandle>>,
    pending: RwLock<HashMap<SessionToken, PendingSession>>,
    expired_sessions: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
struct AgentHandle {
    tx: mpsc::Sender<TunnelCommand>,
}

struct PendingSession {
    tunnel_token: TunnelToken,
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
            agents: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            expired_sessions: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl TunnelRegistry {
    pub async fn register_listener(
        self: &Arc<Self>,
        token: TunnelToken,
        mut connection: LureConnection,
    ) -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel(8);

        // INSERT INTO REGISTRY FIRST (before spawning task)
        {
            let mut agents = self.agents.write().await;
            if agents.contains_key(&token) {
                anyhow::bail!("tunnel token already registered");
            }
            agents.insert(token, AgentHandle { tx: tx.clone() });
        }

        LureLogger::tunnel_agent_registered(&token_prefix(&token.0));

        // SPAWN TASK SECOND (after registration)
        let registry = Arc::clone(self);
        spawn_named("tunnel-agent-listener", async move {
            while let Some(cmd) = rx.recv().await {
                let mut buf = Vec::new();
                match cmd {
                    TunnelCommand::OfferSession { session } => {
                        tun::encode_server_msg(
                            &tun::ServerMsg::SessionOffer(session.0),
                            &mut buf,
                        );
                    }
                }
                if connection.write_all(buf).await.is_err() {
                    break;
                }
            }
            let mut agents = registry.agents.write().await;
            agents.remove(&token);
            LureLogger::tunnel_agent_disconnected(&token_prefix(&token.0));
        })
        .context("failed to spawn tunnel listener task")?;

        Ok(())
    }

    pub async fn offer_session(
        &self,
        token: TunnelToken,
        session: SessionToken,
        target: SocketAddr,
    ) -> anyhow::Result<oneshot::Receiver<LureConnection>> {
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.write().await;
            pending.insert(session, PendingSession { tunnel_token: token, target, respond: tx, created_at: Instant::now() });
        }

        LureLogger::tunnel_session_offered(&token_prefix(&token.0), &target);

        let agent = {
            let agents = self.agents.read().await;
            agents.get(&token).cloned()
        };
        let Some(agent) = agent else {
            let mut pending = self.pending.write().await;
            pending.remove(&session);
            LureLogger::tunnel_agent_missing(&token_prefix(&token.0), &token_prefix(&session.0));
            anyhow::bail!("no active tunnel agent registered for token");
        };

        match agent
            .tx
            .send(TunnelCommand::OfferSession { session })
            .await
        {
            Ok(()) => Ok(rx),
            Err(_) => {
                let mut pending = self.pending.write().await;
                pending.remove(&session);
                LureLogger::tunnel_agent_missing(&token_prefix(&token.0), &token_prefix(&session.0));
                anyhow::bail!("failed to notify tunnel agent")
            }
        }
    }

    pub async fn accept_connect(
        &self,
        token: TunnelToken,
        session: SessionToken,
        mut connection: LureConnection,
    ) -> anyhow::Result<()> {
        let pending = {
            let mut pending = self.pending.write().await;
            pending.remove(&session)
        };
        let Some(pending) = pending else {
            LureLogger::tunnel_session_missing(&token_prefix(&session.0));
            anyhow::bail!("no pending tunnel session");
        };

        // Validate that the provided token matches the one that created this session
        if pending.tunnel_token != token {
            LureLogger::tunnel_token_mismatch(&token_prefix(&token.0), &token_prefix(&session.0));
            anyhow::bail!("tunnel token mismatch: unauthorized accept attempt");
        }

        LureLogger::tunnel_session_accepted(&token_prefix(&token.0), &pending.target);

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
        if !agents.contains_key(&token) {
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
            self.expired_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Tunnel session expired: {:?}", token.0[..8].to_vec());
        }
    }
}
