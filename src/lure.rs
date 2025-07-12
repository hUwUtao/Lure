use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::bail;
use async_trait::async_trait;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::__private::AsDisplay;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};
use valence::prelude::*;
use valence_protocol::packets::{
    handshaking::{handshake_c2s::HandshakeNextState, HandshakeC2s},
    status::{QueryPingC2s, QueryPongS2c, QueryRequestC2s, QueryResponseS2c},
};

use crate::{
    config::LureConfig,
    connection::{Connection, SocketIntent},
    error::ReportableError,
    packet::{create_proxy_protocol_header, OwnedHandshake, OwnedPacket},
    router::{
        status::{QueryResponseKind, StatusBouncer},
        HandshakeOption, RouterInstance, Session,
    },
    telemetry::{event::EventHook, init_event, EventEnvelope, EventServiceInstance},
    threat::{ratelimit::RateLimiterController, ClientIntent, IntentTag, ThreatControlService},
    utils::{leak, OwnedStatic},
};

pub struct Lure {
    config: LureConfig,
    router: &'static RouterInstance,
    status: &'static StatusBouncer,
    threat: &'static ThreatControlService,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct EventIdent {
    id: String,
}

#[async_trait]
impl EventHook<EventEnvelope, EventEnvelope> for EventIdent {
    async fn on_handshake(&self) -> Option<EventEnvelope> {
        Some(EventEnvelope::HandshakeIdent(self.clone()))
    }

    async fn on_event(
        &self,
        _: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        #[cfg(debug_assertions)]
        {
            debug!("RPC-S2C: {:?}", event);
        }
        if let EventEnvelope::Hello(_) = event {
            info!("RPC: Hello")
        }
        Ok(())
    }
}

impl Lure {
    pub fn new(config: LureConfig) -> Lure {
        let router = leak(RouterInstance::new());
        let status = leak(StatusBouncer::new(router, &config));
        Lure {
            config,
            router,
            status,
            threat: leak(ThreatControlService::new()),
        }
    }

    pub async fn start(&'static self) -> anyhow::Result<()> {
        // Listener config.
        let listener_cfg = self.config.bind.to_owned();
        info!("Preparing socket {}", listener_cfg);
        let address: SocketAddr = listener_cfg.parse()?;
        let max_connections = self.config.semaphore.acceptable as usize;

        if !self.config.control.rpc.is_empty() {
            let event = init_event(self.config.control.rpc.clone());
            event
                .hook(EventIdent {
                    id: self.config.inst.clone(),
                })
                .await;
            event.hook(OwnedStatic::from(self.router)).await;
            event.clone().start();
        }

        // Start server.
        let listener = TcpListener::bind(address).await?;
        let semaphore = Arc::new(Semaphore::new(max_connections));
        let rate_limiter: RateLimiterController<IpAddr> =
            RateLimiterController::new(10, Duration::from_secs(3));

        loop {
            // Accept connection first
            let (client, addr) = listener.accept().await?;

            // Apply IP-based rate limiting
            let ip = addr.ip();
            if let crate::threat::ratelimit::RateLimitResult::Disallowed { retry_after: _ra } =
                rate_limiter.check(&ip)
            {
                drop(client);
                continue;
            }

            // Try to acquire semaphore (non-blocking)
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    if let Err(e) = client.set_nodelay(true) {
                        eprintln!("Failed to set TCP_NODELAY: {e}");
                    }

                    let lure = self;
                    tokio::spawn(async move {
                        // Apply timeout to connection handling
                        if let Err(e) = lure.handle_connection(client, addr).await {
                            debug!("connection closed: {e}")
                        }
                        drop(permit);
                    });
                }
                Err(_) => {
                    // Too many connections, reject immediately
                    drop(client);
                }
            }
        }
    }

    pub async fn handle_connection(
        &self,
        client_socket: TcpStream,
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        // Client state
        let (client_read, client_write) = client_socket.into_split();

        let connection = Connection::new(
            address,
            client_read,
            client_write,
            SocketIntent::GreetToProxy,
        );

        self.handle_handshake(connection).await?;
        Ok(())
    }

    pub async fn handle_handshake(&self, mut connection: Connection) -> anyhow::Result<()> {
        // Wait for initial handshake.
        const INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Handshake,
            duration: Duration::from_millis(300),
        };
        let handshake = OwnedHandshake::from_packet(
            self.threat
                .nuisance(connection.recv::<HandshakeC2s>(), INTENT)
                .await??,
        );
        match &handshake.next_state {
            HandshakeNextState::Status => self.handle_status(connection, handshake).await,
            HandshakeNextState::Login => self.handle_proxy(connection, &handshake).await,
        }
    }

    fn get_string(&self, key: &str) -> Box<str> {
        self.config
            .strings
            .get(key)
            .unwrap_or(&"".into())
            .to_owned()
    }

    fn create_placeholder_ping(&self, label: &str) -> anyhow::Result<String> {
        let brand = self.get_string("SERVER_LIST_BRAND");
        let target_label = self.get_string(label);
        let v = json! {
            {
              "version": {
                "name": brand,
                "protocol": -1
              },
              // "players": {
              //   "online": 0,
              //   "max": 0,
              //   "sample": []
              // },
              "description": {
                "text": target_label
              },
              // "favicon": ""
            }
        };
        Ok(serde_json::to_string(&v)?)
    }

    pub async fn handle_status(
        &self,
        mut client: Connection,
        handshake: OwnedHandshake,
    ) -> anyhow::Result<()> {
        const INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Query,
            duration: Duration::from_millis(300),
        };
        self.threat
            .nuisance(client.recv::<QueryRequestC2s>(), INTENT)
            .await??;
        match self.status.get(&handshake.server_address).await {
            QueryResponseKind::Valid(response) => {
                client
                    .send::<QueryResponseS2c>(&response.as_packet())
                    .await?
            }
            QueryResponseKind::NoHost => {
                client
                    .send(&QueryResponseS2c {
                        json: &self.create_placeholder_ping("ROUTE_NOT_FOUND")?,
                    })
                    .await?
            }
            QueryResponseKind::Disconnected => {
                client
                    .send(&QueryResponseS2c {
                        json: &self.create_placeholder_ping("SERVER_OFFLINE")?,
                    })
                    .await?
            }
        }

        let QueryPingC2s { payload } = self
            .threat
            .nuisance(client.recv::<QueryPingC2s>(), INTENT)
            .await??;
        client.send(&QueryPongS2c { payload }).await?;
        Ok(())
    }

    pub async fn handle_proxy(
        &self,
        mut client: Connection,
        handshake: &OwnedHandshake,
    ) -> anyhow::Result<()> {
        let address = client.address;
        if let Ok((session, route)) = self
            .router
            .create_session(&handshake.server_address, address)
            .await
        {
            if let Err(e) = self
                .handle_proxy_session(
                    client,
                    handshake, // &login,
                    &route.handshake,
                    &session,
                )
                .await
            {
                let re = ReportableError::from(e);
                debug!("Proxy session error: {re}");
            }
        } else {
            debug!("No destination");
            client
                .disconnect("No destination".into_text().color(Color::RED))
                .await?;
        }
        self.router.terminate_session(&address).await?;
        Ok(())
    }

    pub async fn handle_proxy_session(
        &self,
        client: Connection,
        handshake: &OwnedHandshake,
        // login: &OwnedLoginHello,
        handshake_option: &HandshakeOption,
        session: &Arc<Session>,
    ) -> anyhow::Result<()> {
        let server_address = session.destination_addr;
        let connect_result =
            timeout(Duration::from_secs(1), TcpStream::connect(server_address)).await;

        async fn handle_err(mut client: Connection, err: &ReportableError) -> anyhow::Result<()> {
            // let re = ;
            let error = format!("Gateway error:\n\n{}", err.as_display());
            client
                .disconnect(error.clone().into_text().color(Color::RED))
                .await?;
            Ok(())
        }

        let server_stream: TcpStream = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                let err = ReportableError::from(err);
                handle_err(client, &err).await?;
                bail!(err);
            }
            Err(err) => {
                let err = ReportableError::from(err);
                handle_err(client, &err).await?;
                bail!(err);
            }
        };

        if let Err(e) = server_stream.set_nodelay(true) {
            eprintln!("Failed to set TCP_NODELAY: {e}");
        }

        let (server_read, server_write) = server_stream.into_split();

        let mut server = Connection::new(
            server_address,
            server_read,
            server_write,
            SocketIntent::GreetToBackend,
        );

        // Replay necessary packets
        if let HandshakeOption::HAProxy = handshake_option {
            let pkt = create_proxy_protocol_header(client.address)?;
            server.send_raw(&pkt).await?;
        }

        server.send(&handshake.as_packet()).await?;
        // server.send(&login.as_packet()).await?;

        self.passthrough_now(client, server).await?;
        Ok(())
    }

    async fn passthrough_now(&self, client: Connection, server: Connection) -> anyhow::Result<()> {
        let mut client_to_server = Connection::new(
            client.address,
            client.read,
            server.write,
            SocketIntent::PassthroughServerBound,
        );
        let mut server_to_client = Connection::new(
            server.address,
            server.read,
            client.write,
            SocketIntent::PassthroughClientBound,
        );

        let c2s_fut: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            loop {
                let bytes = client_to_server.copy().await?;
                if bytes == 0 {
                    break;
                }
            }
            Ok(())
        });

        let s2c_fut = async move {
            loop {
                let bytes = server_to_client.copy().await?;
                if bytes == 0 {
                    break;
                }
            }
            Ok(())
        };

        tokio::select! {
            c2s = c2s_fut => Ok(c2s??),
            s2c = s2c_fut => s2c,
        }
    }
}
