use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::Context;
use tokio::sync::{RwLock, mpsc, oneshot};

use crate::{sock::LureConnection, utils::spawn_named};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TunnelToken(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionToken(pub [u8; 32]);

pub struct TunnelRegistry {
    agents: RwLock<HashMap<TunnelToken, AgentHandle>>,
    pending: RwLock<HashMap<SessionToken, PendingSession>>,
}

#[derive(Clone)]
struct AgentHandle {
    tx: mpsc::Sender<TunnelCommand>,
}

struct PendingSession {
    target: SocketAddr,
    respond: oneshot::Sender<LureConnection>,
}

enum TunnelCommand {
    OfferSession { session: SessionToken },
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
        }
    }
}

impl TunnelRegistry {
    pub async fn register_listener(
        self: &Arc<Self>,
        token: TunnelToken,
        mut connection: LureConnection,
    ) -> anyhow::Result<()> {
        {
            let agents = self.agents.read().await;
            if agents.contains_key(&token) {
                anyhow::bail!("tunnel token already registered");
            }
        }

        let (tx, mut rx) = mpsc::channel(8);

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
        })
        .context("failed to spawn tunnel listener task")?;

        let mut agents = self.agents.write().await;
        agents.insert(token, AgentHandle { tx });

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
            pending.insert(session, PendingSession { target, respond: tx });
        }

        let agent = {
            let agents = self.agents.read().await;
            agents.get(&token).cloned()
        };
        let Some(agent) = agent else {
            let mut pending = self.pending.write().await;
            pending.remove(&session);
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
            anyhow::bail!("no pending tunnel session");
        };

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
}
