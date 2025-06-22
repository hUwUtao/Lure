use crate::connection::connection::Connection;
use crate::router::{HandshakeOption, Route, RouterInstance};
use anyhow::bail;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use opentelemetry::metrics::Meter;
use tokio::sync::RwLock;
use tokio::time::timeout;
use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState;
use valence_protocol::packets::handshaking::HandshakeC2s;
use valence_protocol::packets::status::{QueryRequestC2s, QueryResponseS2c};
use valence_protocol::{Bounded, VarInt};
use crate::packet::{create_proxy_protocol_header, OwnedPacket, OwnedQueryResponse, NULL_SOCKET};

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

type Resolved = (SocketAddr, Arc<Route>);

impl StatusBouncer {
    /// Create a new StatusBouncer with default cache duration of 30 seconds
    pub fn new(router: Arc<RouterInstance>) -> Self {
        StatusBouncer {
            cache: RwLock::new(HashMap::new()),
            router,
            cache_duration: 1,
        }
    }

    async fn request(&self, hostname: &str, resolved: &Resolved) -> anyhow::Result<QueryResponseKind> {
        if let Ok(mut conn) = Connection::create_conn(resolved.0).await {
            match resolved.1.handshake {
                HandshakeOption::HAProxy => {
                    let pkt = create_proxy_protocol_header(NULL_SOCKET)?;
                    conn.send_raw(&pkt).await?;
                }
                _ => {}
            }
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

    async fn update(&self, hostname: &str, resolved: Resolved) -> QueryResponseKind {
        match timeout(Duration::from_secs(2), self.request(hostname, &resolved)).await {
            Err(_) => QueryResponseKind::Disconnected,
            Ok(Err(_)) => QueryResponseKind::Disconnected,
            Ok(Ok(kind)) => {
                if let QueryResponseKind::Valid(response) = kind.clone() {
                    self.cache
                        .write()
                        .await
                        .insert(resolved.0, Arc::new((response, self.current_timestamp())));
                }
                kind
            }
        }
    }

    /// Get cached response for a server address
    pub async fn get(&self, hostname: &str) -> QueryResponseKind {
        if let Some(resolved) = self.router.resolve(hostname).await {
            if let Some(cached) = {
                let lock = self.cache.read().await;
                let val = lock.get(&resolved.0).cloned();
                drop(lock);
                val
            } {
                let current_time = self.current_timestamp();
                let (_, timestamp) = cached.as_ref();

                // Check if cache is still valid
                if current_time - timestamp < self.cache_duration {
                    QueryResponseKind::Valid(cached.0.clone())
                } else {
                    self.update(hostname, resolved).await
                }
            } else {
                self.update(hostname, resolved).await
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
