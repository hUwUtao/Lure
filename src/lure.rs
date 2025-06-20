use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::bail;
use log::__private_api::loc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use tokio::task::JoinHandle;
use valence::prelude::*;

use crate::config::LureConfig;
use crate::connection::connection::Connection;
use crate::router::status::{QueryResponseKind, StatusBouncer};
use crate::router::{Route, RouterInstance, Session};
use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState;
use valence_protocol::packets::handshaking::HandshakeC2s;
use valence_protocol::packets::status::{
    QueryPingC2s, QueryPongS2c, QueryRequestC2s, QueryResponseS2c,
};
use valence_protocol::{Bounded, VarInt};
use valence_protocol::packets::login::LoginHelloC2s;
use crate::packet::{OwnedHandshake, OwnedLoginHello, OwnedPacket};

#[derive(Clone, Debug)]
pub struct Lure {
    config: LureConfig,
    router: Arc<RouterInstance>,
    status: Arc<StatusBouncer>,
}

impl Lure {
    pub fn new(config: LureConfig) -> Lure {
        let router = Arc::new(RouterInstance::new());
        let status = Arc::new(StatusBouncer::new(router.clone()));
        Lure {
            config,
            router,
            status,
        }
    }

    pub async fn start(&'static mut self) -> anyhow::Result<()> {
        // Listener config.
        let listener_cfg = self.config.listener.to_owned();
        println!("Preparing socket {}", listener_cfg.bind);
        let address: SocketAddr = listener_cfg.bind.parse()?;
        let max_connections = listener_cfg.max_connections;

        self.router
            .apply_route(Route {
                id: 0,
                matchers: vec!["localhost".to_string()],
                endpoints: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 25565)],
                disabled: false,
                priority: 0,
            })
            .await;

        // Start server.
        let listener = TcpListener::bind(address).await?;
        let semaphore = Arc::new(Semaphore::new(max_connections));


        loop {
            // Accept connection first
            let (client, addr) = listener.accept().await?;

            // Apply IP-based rate limiting
            let ip = addr.ip();
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
                        if let Err(_) = lure.handle_connection(client, addr).await {}

                        drop(permit);
                    });
                },
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

        let connection = Connection::new(address, client_read, client_write);

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
        if let Some(session) = self
            .router
            .create_session(&handshake.server_address, address)
            .await
        {
            if let Err(_e) = self.handle_proxy_session(
                client, handshake,
                // &login,
                &session
            ).await {
            } else {
            }
            self.router.terminate_session(&address).await;
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

        let mut server = Connection::new(server_address, server_read, server_write);

        // Replay necessary packets
        server.send(&handshake.as_packet()).await?;
        // server.send(&login.as_packet()).await?;

        self.passthrough_now(client, server).await?;
        Ok(())
    }

    async fn passthrough_now(&self, client: Connection, server: Connection) -> anyhow::Result<()> {
        let mut client_to_server =
            Connection::new(client.address.clone(), client.read, server.write);
        let mut server_to_client =
            Connection::new(server.address.clone(), server.read, client.write);

        let c2s_fut: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            loop {
                client_to_server.raw_pipe().await?;
            }
        });

        let s2c_fut = async move {
            loop {
                server_to_client.raw_pipe().await?;
            }
        };

        tokio::select! {
            c2s = c2s_fut => Ok(c2s??),
            s2c = s2c_fut => s2c,
        }
    }
}
