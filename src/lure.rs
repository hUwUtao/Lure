use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::bail;
use async_trait::async_trait;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use tokio::task::JoinHandle;
use valence::prelude::*;

use crate::config::LureConfig;
use crate::connection::connection::{Connection, SocketIntent};
use crate::packet::{create_proxy_protocol_header, OwnedHandshake, OwnedPacket};
use crate::router::status::{QueryResponseKind, StatusBouncer};
use crate::router::{HandshakeOption, Route, RouterInstance, Session};
use crate::telemetry::event::EventHook;
use crate::telemetry::{init_event, EventEnvelope, EventServiceInstance};
use crate::utils::OwnedArc;
use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState;
use valence_protocol::packets::handshaking::HandshakeC2s;
use valence_protocol::packets::status::{
    QueryPingC2s, QueryPongS2c, QueryRequestC2s, QueryResponseS2c,
};

#[derive(Clone, Debug)]
pub struct Lure {
    config: LureConfig,
    router: Arc<RouterInstance>,
    status: Arc<StatusBouncer>,
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
        let router = Arc::new(RouterInstance::new());
        let status = Arc::new(StatusBouncer::new(router.clone(), &config));
        Lure {
            config,
            router,
            status,
        }
    }

    pub async fn start(&'static mut self) -> anyhow::Result<()> {
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
            event.hook(OwnedArc::from(self.router.clone())).await;
            event.clone().start();
        }

        // Start server.
        let listener = TcpListener::bind(address).await?;
        let semaphore = Arc::new(Semaphore::new(max_connections));

        loop {
            // Accept connection first
            let (client, addr) = listener.accept().await?;

            // Apply IP-based rate limiting
            // let ip = addr.ip();
            // let should_accept = rate_limiters
            //     .entry(ip)
            //     .or_insert_with(|| RateLimiter::new(Duration::from_millis(100)))
            //     .check();

            // if !should_accept {
            //     drop(client);
            //     continue;
            // }

            // Try to acquire semaphore (non-blocking)
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    if let Err(e) = client.set_nodelay(true) {
                        eprintln!("Failed to set TCP_NODELAY: {e}");
                    }

                    let lure = self.clone();
                    tokio::spawn(async move {
                        // Apply timeout to connection handling
                        if let Err(e) = lure.handle_connection(client, addr).await {
                            error!("connection closed: {e}")
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

        // while let Ok(permit) = semaphore.clone().acquire_owned().await {
        // // loop {
        //     let (client, remote_client_addr) = listener.accept().await?;
        //     // eprintln!("Accepted connection to {remote_client_addr}");
        //
        //     if let Err(e) = client.set_nodelay(true) {
        //         eprintln!("Failed to set TCP_NODELAY: {e}");
        //     }
        //
        //     let lure = self.clone();
        //     tokio::spawn(async move {
        //         if let Err(e) = lure.handle_connection(client, remote_client_addr).await {
        //             eprintln!("Connection to {remote_client_addr} ended with: {e}");
        //         } else {
        //             // eprintln!("Connection to {remote_client_addr} ended.");
        //         }
        //
        //         drop(permit);
        //     });
        // }
        //
        // println!("Starting Lure server.");
        // Ok(())
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
        let handshake = OwnedHandshake::from_packet(connection.recv::<HandshakeC2s>().await?);
        match &handshake.next_state {
            HandshakeNextState::Status => self.handle_status(connection, handshake).await,
            HandshakeNextState::Login => self.handle_proxy(connection, &handshake).await,
        }
    }

    pub async fn handle_status(
        &self,
        mut client: Connection,
        handshake: OwnedHandshake,
    ) -> anyhow::Result<()> {
        client.recv::<QueryRequestC2s>().await?;
        match self.status.get(&handshake.server_address).await {
            QueryResponseKind::Valid(response) => client.send::<QueryResponseS2c>(&response.as_packet()).await?,
            QueryResponseKind::NoHost => client
                .send(&QueryResponseS2c {
                    json: "{\"version\":{\"name\":\"azurepowered\",\"protocol\":-1},\"players\":{\"online\":0,\"max\":0,\"sample\":[]},\"description\":\"ROUTE NOT FOUND\",\"favicon\":\"\"}",
                })
                .await?,
            QueryResponseKind::Disconnected => client
                .send(&QueryResponseS2c {
                    json: "{\"version\":{\"name\":\"azurepowered\",\"protocol\":-1},\"players\":{\"online\":0,\"max\":0,\"sample\":[]},\"description\":\"SERVER OFFLINE\",\"favicon\":\"\"}",
                })
                .await?
        }

        let QueryPingC2s { payload } = client.recv::<QueryPingC2s>().await?;
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
            if let Err(_e) = self
                .handle_proxy_session(
                    client,
                    handshake, // &login,
                    &route.handshake,
                    &session,
                )
                .await
            {
            } else {
            }
            self.router.terminate_session(&address).await?;
            Ok(())
        } else {
            client
                .disconnect("No destination".into_text().color(Color::RED))
                .await?;
            Ok(())
        }
    }

    pub async fn handle_proxy_session(
        &self,
        mut client: Connection,
        handshake: &OwnedHandshake,
        // login: &OwnedLoginHello,
        handshake_option: &HandshakeOption,
        session: &Arc<Session>,
    ) -> anyhow::Result<()> {
        let server_address = session.destination_addr;
        let connect_result = TcpStream::connect(server_address).await;

        let server_stream: TcpStream = match TcpStream::connect(server_address).await {
            Ok(stream) => stream,
            Err(_) => {
                let error = format!("Cannot connect to server:\n\n{:?}", connect_result.err());
                client
                    .disconnect(error.clone().into_text().color(Color::RED))
                    .await?;
                bail!(error);
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
        match handshake_option {
            HandshakeOption::HAProxy => {
                let pkt = create_proxy_protocol_header(client.address)?;
                server.send_raw(&pkt).await?;
            }
            _ => {}
        }

        server.send(&handshake.as_packet()).await?;
        // server.send(&login.as_packet()).await?;

        self.passthrough_now(client, server).await?;
        Ok(())
    }

    async fn passthrough_now(&self, client: Connection, server: Connection) -> anyhow::Result<()> {
        let mut client_to_server = Connection::new(
            client.address.clone(),
            client.read,
            server.write,
            SocketIntent::PassthroughServerBound,
        );
        let mut server_to_client = Connection::new(
            server.address.clone(),
            server.read,
            client.write,
            SocketIntent::PassthroughClientBound,
        );

        let c2s_fut: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            loop {
                client_to_server.copy().await?;
            }
        });

        let s2c_fut = async move {
            loop {
                server_to_client.copy().await?;
            }
        };

        tokio::select! {
            c2s = c2s_fut => Ok(c2s??),
            s2c = s2c_fut => s2c,
        }
    }
}
