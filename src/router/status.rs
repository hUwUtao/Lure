use crate::connection::connection::Connection;
use crate::router::RouterInstance;
use anyhow::bail;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use opentelemetry::metrics::Meter;
use tokio::sync::RwLock;
use tokio::time::timeout;
use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState;
use valence_protocol::packets::handshaking::HandshakeC2s;
use valence_protocol::packets::status::{QueryRequestC2s, QueryResponseS2c};
use valence_protocol::{Bounded, VarInt};
use crate::packet::{OwnedPacket, OwnedQueryResponse};

#[derive(Debug, Clone)]
pub enum QueryResponseKind {
    Valid(OwnedQueryResponse),
    NoHost,
    Disconnected,
}

#[derive(Debug)]
pub struct StatusBouncer {
    cache: RwLock<HashMap<SocketAddr, Arc<(OwnedQueryResponse, u64)>>>,
    router: Arc<RouterInstance>,
    cache_duration: u64, // Cache duration in seconds
}

impl StatusBouncer {
    /// Create a new StatusBouncer with default cache duration of 30 seconds
    pub fn new(router: Arc<RouterInstance>, meter: &Meter) -> Self {
        StatusBouncer {
            cache: RwLock::new(HashMap::new()),
            router,
            cache_duration: 1,
        }
    }

    async fn request(&self, hostname: &str, addr: SocketAddr) -> anyhow::Result<QueryResponseKind> {
        if let Ok(mut conn) = Connection::create_conn(addr).await {
            conn.send(&HandshakeC2s {
                protocol_version: VarInt(770),
                server_address: Bounded(hostname),
                server_port: 0,
                next_state: HandshakeNextState::Status,
            })
            .await?;
            conn.send(&QueryRequestC2s {}).await?;
            Ok(QueryResponseKind::Valid(OwnedQueryResponse::from_packet(
                conn.recv::<QueryResponseS2c>().await?.clone(),
            )))
        } else {
            bail!("Failed to connect to server");
        }
    }

    async fn update(&self, hostname: &str, addr: SocketAddr) -> QueryResponseKind {
        match timeout(Duration::from_secs(2), self.request(hostname, addr)).await {
            Err(_) => QueryResponseKind::Disconnected,
            Ok(Err(_)) => QueryResponseKind::Disconnected,
            Ok(Ok(kind)) => {
                if let QueryResponseKind::Valid(response) = kind.clone() {
                    self.cache
                        .write()
                        .await
                        .insert(addr, Arc::new((response, self.current_timestamp())));
                }
                kind
            }
        }
    }

    /// Get cached response for a server address
    pub async fn get(&self, hostname: &str) -> QueryResponseKind {
        if let Some((addr, _route)) = self.router.resolve(hostname).await {
            if let Some(cached) = {
                let lock = self.cache.read().await;
                let val = lock.get(&addr).cloned();
                drop(lock);
                val
            } {
                let current_time = self.current_timestamp();
                let (_, timestamp) = cached.as_ref();

                // Check if cache is still valid
                if current_time - timestamp < self.cache_duration {
                    QueryResponseKind::Valid(cached.0.clone())
                } else {
                    self.update(hostname, addr).await
                }
            } else {
                self.update(hostname, addr).await
            }
        } else {
            QueryResponseKind::NoHost
        }
    }

    /// Helper method to get current timestamp
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
