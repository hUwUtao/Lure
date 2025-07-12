use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{sync::RwLock, time::timeout};
use valence_protocol::{
    packets::{
        handshaking::{handshake_c2s::HandshakeNextState, HandshakeC2s},
        status::{QueryRequestC2s, QueryResponseS2c},
    },
    Bounded, VarInt,
};

use crate::{
    config::LureConfig,
    connection::Connection,
    packet::{create_proxy_protocol_header, OwnedQueryResponse, NULL_SOCKET},
    router::{HandshakeOption, Route, RouterInstance},
};

#[derive(Debug, Clone)]
pub enum QueryResponseKind {
    Valid(OwnedQueryResponse),
    NoHost,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplePlayer {
    name: String,
    id: String,
}

impl SamplePlayer {
    fn uuid_from_number(n: u64) -> String {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&n.to_be_bytes());

        let mut uuid = String::with_capacity(36);
        for (i, byte) in bytes.iter().enumerate() {
            uuid.push_str(&format!("{:02x}", byte));
            if matches!(i, 3 | 5 | 7 | 9) {
                uuid.push('-');
            }
        }
        uuid
    }

    pub fn create_fake_list(list: &[String]) -> Vec<Value> {
        let mut flist: Vec<Value> = Vec::new();
        for (i, name) in list.iter().enumerate() {
            flist.push(json!(
                {
                    "name": name.clone(),
                    "id": Self::uuid_from_number(i as u64),
                }
            ))
        }
        flist
    }
}

#[derive(Debug)]
pub struct StatusBouncer {
    cache: RwLock<HashMap<u64, Arc<(OwnedQueryResponse, u64)>>>,
    router: &'static RouterInstance,
    cache_duration: u64, // Cache duration in seconds
    override_players: Vec<Value>,
}

type Resolved = (SocketAddr, Arc<Route>);

impl StatusBouncer {
    /// Create a new StatusBouncer with default cache duration of 30 seconds
    pub fn new(router: &'static RouterInstance, config: &LureConfig) -> Self {
        let override_players = if let Some(t) = &config.misc.override_players {
            t
        } else {
            &vec![]
        };
        StatusBouncer {
            cache: RwLock::new(HashMap::new()),
            router,
            cache_duration: 1,
            override_players: SamplePlayer::create_fake_list(override_players),
        }
    }

    async fn transform_query(
        &self,
        json_raw: &'_ str,
        route: &Arc<Route>,
    ) -> anyhow::Result<String> {
        if route.override_query {
            let mut tree: Value = serde_json::from_str(json_raw)?;
            if let Some(p) = tree.get_mut("players") {
                if let Some(mp) = p.as_object_mut() {
                    let a = self.override_players.clone();
                    mp.insert("sample".into(), Value::Array(a));
                }
            } else {
                error!("Query doesnt have players");
            }
            Ok(serde_json::to_string(&tree)?)
        } else {
            Ok(json_raw.to_string())
        }
    }

    async fn request(
        &self,
        hostname: &str,
        resolved: &Resolved,
    ) -> anyhow::Result<QueryResponseKind> {
        if let Ok(mut conn) = Connection::create_conn(resolved.0).await {
            if let HandshakeOption::HAProxy = resolved.1.handshake {
                let pkt = create_proxy_protocol_header(NULL_SOCKET)?;
                conn.send_raw(&pkt).await?;
            }
            conn.send(&HandshakeC2s {
                protocol_version: VarInt(770),
                server_address: Bounded(hostname),
                server_port: 0,
                next_state: HandshakeNextState::Status,
            })
            .await?;
            conn.send(&QueryRequestC2s {}).await?;
            let packet = conn.recv::<QueryResponseS2c>().await?;
            Ok(QueryResponseKind::Valid(OwnedQueryResponse::new(
                &self.transform_query(packet.json, &resolved.1).await?,
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
                    self.cache.write().await.insert(
                        resolved.1.id,
                        Arc::new((response, self.current_timestamp())),
                    );
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
                let val = lock.get(&resolved.1.id).cloned();
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
