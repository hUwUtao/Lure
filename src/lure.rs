use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use log::{debug, info};
use net::{
    HandshakeC2s, HandshakeNextState, PacketDecoder, ProtoError, StatusPingC2s, StatusPongS2c,
    StatusRequestC2s, StatusResponseS2c, encode_raw_packet,
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, Semaphore},
    task::yield_now,
    time::{error::Elapsed, timeout},
};

use crate::{
    config::LureConfig,
    connection::{EncodedConnection, SocketIntent},
    error::{ErrorResponder, ReportableError},
    logging::LureLogger,
    metrics::HandshakeMetrics,
    packet::{OwnedHandshake, OwnedLoginStart, OwnedPacket},
    router::{Profile, ResolvedRoute, Route, RouterInstance, Session, SessionHandle},
    sock::{BackendKind, Listener, backend_kind, passthrough_now},
    telemetry::{EventEnvelope, EventServiceInstance, event::EventHook, get_meter, init_event},
    threat::{
        ClientFail, ClientIntent, IntentTag, ThreatControlService, ratelimit::RateLimiterController,
    },
    tunnel::{SessionToken, TunnelRegistry, TunnelToken},
    utils::{OwnedStatic, leak, spawn_named},
};
use getrandom::fill as fill_random;
mod backend;
mod query;
pub struct Lure {
    config: RwLock<LureConfig>,
    router: &'static RouterInstance,
    threat: &'static ThreatControlService,
    metrics: HandshakeMetrics,
    errors: ErrorResponder,
    tunnels: Arc<TunnelRegistry>,
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
        router.set_instance_name(config.inst.clone());
        Lure {
            config: RwLock::new(config),
            router,
            threat: leak(ThreatControlService::new()),
            metrics: HandshakeMetrics::new(&get_meter()),
            errors: ErrorResponder::new(),
            tunnels: Arc::new(TunnelRegistry::default()),
        }
    }

    async fn config_snapshot(&self) -> LureConfig {
        self.config.read().await.clone()
    }

    async fn install_routes(&'static self, routes: Vec<Route>) {
        self.router.clear_routes().await;
        for route in routes {
            self.router.apply_route(route).await;
        }
    }

    pub async fn sync_routes_from_config(&'static self) -> anyhow::Result<()> {
        let snapshot = self.config_snapshot().await;
        let routes = snapshot.default_routes()?;
        self.install_routes(routes).await;
        Ok(())
    }

    pub async fn reload_config(&'static self, config: LureConfig) -> anyhow::Result<()> {
        let routes = config.default_routes()?;
        self.install_routes(routes).await;
        {
            *self.config.write().await = config;
        }
        Ok(())
    }

    pub async fn start(&'static self) -> anyhow::Result<()> {
        // Listener config.
        let config = self.config_snapshot().await;
        let listener_cfg = config.bind.clone();
        LureLogger::preparing_socket(&listener_cfg);
        let address: SocketAddr = listener_cfg.parse()?;
        let max_connections = config.max_conn as usize;
        let cooldown = Duration::from_secs(config.cooldown);
        let inst = config.inst.clone();
        drop(config);

        if let Ok(rpc_url) = dotenvy::var("LURE_RPC") {
            let event = init_event(rpc_url);
            event.hook(EventIdent { id: inst }).await;
            event.hook(OwnedStatic::from(self.router)).await;
            event
                .hook(crate::inspect::InspectHook::new(self.router))
                .await;
            event.clone().start();
        }

        // Start server.
        let listener = Listener::bind(address).await?;
        let semaphore = Arc::new(Semaphore::new(max_connections));
        let rate_limiter: RateLimiterController<IpAddr> = RateLimiterController::new(10, cooldown);

        loop {
            // Accept connection first
            let (client, addr) = listener.accept().await?;

            self.metrics.record_open();

            // Apply IP-based rate limiting
            let ip = addr.ip();
            if let crate::threat::ratelimit::RateLimitResult::Disallowed { retry_after: _ra } =
                rate_limiter.check(&ip)
            {
                LureLogger::rate_limited(&ip);
                drop(client);
                continue;
            }

            // Try to acquire semaphore (non-blocking)
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    if dotenvy::var("NO_NODELAY").is_err()
                        && let Err(e) = client.set_nodelay(true)
                    {
                        LureLogger::tcp_nodelay_failed(&e);
                    }

                    let lure = self;
                    let handler = async move {
                        // Apply timeout to connection handling
                        if let Err(e) = lure.handle_connection(client, addr).await {
                            LureLogger::connection_closed(&addr, &e);
                        }
                        drop(permit);
                    };
                    if backend_kind() == BackendKind::Uring {
                        net::sock::uring::spawn(handler);
                    } else {
                        spawn_named("Connection handler", handler)?;
                    }
                }
                Err(_) => {
                    // Too many connections, reject immediately
                    drop(client);
                }
            }
            yield_now().await;
        }
    }

    async fn handle_connection(
        &self,
        client_socket: crate::sock::Connection,
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        LureLogger::new_connection(&address);

        self.handle_handshake(client_socket).await?;
        Ok(())
    }

    async fn handle_handshake(
        &self,
        mut connection: crate::sock::Connection,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        let client_addr = *connection.addr();
        const HANDSHAKE_INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Handshake,
            duration: Duration::from_secs(5),
        };
        let ingress = self
            .threat
            .nuisance(self.read_ingress_hello(&mut connection), HANDSHAKE_INTENT)
            .await
            .inspect_err(|err| {
                if let Some(ClientFail::Timeout { intent, .. }) = err.downcast_ref::<ClientFail>() {
                    LureLogger::deadline_missed(
                        "client handshake",
                        intent.duration,
                        Some(&client_addr),
                        None,
                    );
                } else {
                    LureLogger::parser_failure(&client_addr, "client handshake", err);
                }
            })?
            .inspect_err(|err| {
                LureLogger::parser_failure(&client_addr, "client handshake", err);
            })?;

        let (hs, buffered, handshake_raw) = match ingress {
            IngressHello::Minecraft {
                handshake,
                buffered,
                raw,
            } => (handshake, buffered, raw),
            IngressHello::Tunnel { hello } => {
                self.handle_tunnel_ingress(connection, hello).await?;
                return Ok(());
            }
        };

        let handler =
            EncodedConnection::with_buffered(&mut connection, SocketIntent::GreetToProxy, buffered);
        let state_attr = match hs.next_state {
            HandshakeNextState::Status => "status",
            HandshakeNextState::Login => "login",
        };
        self.metrics.record_attempt(state_attr);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        LureLogger::handshake_completed(elapsed_ms, state_attr);
        self.metrics.record_duration(elapsed_ms, state_attr);

        let resolved = match timeout(
            Duration::from_secs(1),
            self.router.resolve(&hs.get_stripped_hostname()),
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(_) => {
                LureLogger::deadline_missed(
                    "router.resolve",
                    Duration::from_secs(1),
                    Some(&client_addr),
                    Some(&hs.server_address),
                );
                None
            }
        };

        match hs.next_state {
            HandshakeNextState::Status => self.handle_status(handler, &hs, resolved).await,
            HandshakeNextState::Login => {
                self.handle_proxy(handler, &hs, resolved, handshake_raw).await
            }
        }
    }

    async fn handle_status(
        &self,
        mut client: EncodedConnection<'_>,
        handshake: &OwnedHandshake,
        resolved: Option<ResolvedRoute>,
    ) -> anyhow::Result<()> {
        const INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Query,
            duration: Duration::from_secs(1),
        };
        let client_addr = *client.as_inner().addr();
        let config = self.config_snapshot().await;
        let Some(resolved) = resolved else {
            self.status_error(&mut client, &config).await?;
            return Ok(());
        };

        let backend_addr = resolved.endpoint;
        let backend_label = backend_addr.to_string();

        let mut backend = match backend::connect(
            backend_addr,
            handshake,
            Some(resolved.endpoint_host.as_str()),
            backend_addr.port(),
            resolved.route.preserve_host(),
            resolved.route.proxied(),
            &config,
            client_addr,
        )
        .await
        {
            Ok(connection) => connection,
            Err(backend::BackendConnectError::Connect(err)) => {
                if err.downcast_ref::<Elapsed>().is_some() {
                    LureLogger::deadline_missed(
                        "backend connect",
                        Duration::from_secs(3),
                        Some(&client_addr),
                        Some(&backend_label),
                    );
                } else {
                    LureLogger::backend_failure(Some(&client_addr), backend_addr, "connect", &err);
                }
                self.status_error(&mut client, &config).await?;
                return Ok(());
            }
            Err(backend::BackendConnectError::Handshake(err)) => {
                if err.downcast_ref::<Elapsed>().is_some() {
                    LureLogger::deadline_missed(
                        "backend handshake",
                        Duration::from_secs(1),
                        Some(&client_addr),
                        Some(&backend_label),
                    );
                } else {
                    LureLogger::backend_failure(
                        Some(&client_addr),
                        backend_addr,
                        "handshake",
                        &err,
                    );
                }
                self.status_error(&mut client, &config).await?;
                return Ok(());
            }
        };

        let mut server = EncodedConnection::new(&mut backend, SocketIntent::GreetToBackend);

        let req = match self
            .threat
            .nuisance(client.recv::<StatusRequestC2s>(), INTENT)
            .await
        {
            Ok(Ok(packet)) => packet,
            Ok(Err(err)) => {
                LureLogger::parser_failure(&client_addr, "client status query request", &err);
                return Err(err);
            }
            Err(err) => {
                if let Some(ClientFail::Timeout { intent, .. }) = err.downcast_ref::<ClientFail>() {
                    LureLogger::deadline_missed(
                        "client status query request",
                        intent.duration,
                        Some(&client_addr),
                        None,
                    );
                } else {
                    LureLogger::parser_failure(&client_addr, "client status query request", &err);
                }
                return Err(err);
            }
        };

        server.send(&req).await?;

        let response = match server.recv::<StatusResponseS2c>().await {
            Ok(r) => r,
            Err(err) => {
                LureLogger::parser_failure(&client_addr, "backend status response", &err);
                self.status_error(&mut client, &config).await?;
                return Ok(());
            }
        };
        client.send(&response).await?;

        let ping = match self
            .threat
            .nuisance(client.recv::<StatusPingC2s>(), INTENT)
            .await
        {
            Ok(Ok(packet)) => packet,
            Ok(Err(err)) => {
                LureLogger::parser_failure(&client_addr, "client status ping", &err);
                return Err(err);
            }
            Err(err) => {
                if let Some(ClientFail::Timeout { intent, .. }) = err.downcast_ref::<ClientFail>() {
                    LureLogger::deadline_missed(
                        "client status ping",
                        intent.duration,
                        Some(&client_addr),
                        None,
                    );
                } else {
                    LureLogger::parser_failure(&client_addr, "client status ping", &err);
                }
                return Err(err);
            }
        };
        server.send(&ping).await?;
        match server.recv::<StatusPongS2c>().await {
            Ok(pong) => client.send(&pong).await?,
            Err(err) => {
                LureLogger::parser_failure(&client_addr, "backend status pong", &err);
                self.metrics.record_failure("status");
                client
                    .send(&StatusPongS2c {
                        payload: ping.payload,
                    })
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_proxy<'a>(
        &self,
        mut client: EncodedConnection<'a>,
        handshake: &OwnedHandshake,
        resolved: Option<ResolvedRoute>,
        handshake_raw: Vec<u8>,
    ) -> anyhow::Result<()> {
        const INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Handshake,
            duration: Duration::from_secs(5),
        };

        let (login, login_raw) = {
            let login_frame = self
                .threat
                .nuisance(client.recv_login_start(handshake.protocol_version), INTENT)
                .await??;
            (
                OwnedLoginStart::from_packet(login_frame.packet),
                login_frame.raw,
            )
        };
        let profile = Arc::new(Profile {
            name: Arc::clone(&login.username),
            uuid: login.profile_id,
        });

        let address = *client.as_inner().addr();
        let hostname = handshake.get_stripped_hostname();
        let hostname = hostname.as_ref();

        let Some(resolved) = resolved else {
            self.disconnect_login(&mut client, address, |config| {
                (
                    config.string_value("ROUTE_NOT_FOUND"),
                    format!("ROUTE_NOT_FOUND: route '{hostname}' not found"),
                )
            })
            .await;
            return Ok(());
        };

        let Some((session, route)) = self
            .create_proxy_session(&mut client, address, hostname, &resolved, profile)
            .await
        else {
            return Ok(());
        };

        let server_address = session.destination_addr;
        if route.tunnel() {
            let _ = self
                .handle_tunnel_session(
                    client,
                    handshake_raw,
                    &login_raw,
                    route.as_ref(),
                    &session,
                )
                .await
                .map_err(|e| {
                    let re = ReportableError::from(e);
                    LureLogger::connection_error(&address, Some(&server_address), &re);
                    re
                });
        } else {
            let _ = self
                .handle_proxy_session(client, handshake, route.as_ref(), &session, &login_raw)
                .await
                .map_err(|e| {
                    let re = ReportableError::from(e);
                    LureLogger::connection_error(&address, Some(&server_address), &re);
                    re
                });
        }

        Ok(())
    }

    async fn handle_tunnel_session(
        &self,
        mut client: EncodedConnection<'_>,
        handshake_raw: Vec<u8>,
        login_raw: &[u8],
        route: &Route,
        session: &Session,
    ) -> anyhow::Result<()> {
        let Some(token) = route.tunnel_token else {
            self.disconnect_login(&mut client, session.client_addr, |config| {
                (
                    config.string_value("TUNNEL_TOKEN_MISSING"),
                    "TUNNEL_TOKEN_MISSING: route missing tunnel token",
                )
            })
            .await;
            return Ok(());
        };

        let mut session_bytes = [0u8; 32];
        fill_random(&mut session_bytes)?;
        let session_token = SessionToken(session_bytes);

        let receiver = self
            .tunnels
            .offer_session(TunnelToken(token), session_token, session.destination_addr)
            .await?;

        let mut agent_connection = match timeout(Duration::from_secs(10), receiver).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) => anyhow::bail!("tunnel agent dropped session"),
            Err(_) => anyhow::bail!("tunnel agent connect timeout"),
        };

        let mut agent = EncodedConnection::new(&mut agent_connection, SocketIntent::GreetToBackend);
        agent.send_raw(&handshake_raw).await?;
        agent.send_raw(login_raw).await?;

        let pending = client.take_pending_inbound();
        if !pending.is_empty() {
            agent.send_raw(&pending).await?;
        }

        passthrough_now(&mut client, &mut agent, session).await?;
        Ok(())
    }

    async fn handle_tunnel_ingress(
        &self,
        connection: crate::sock::Connection,
        hello: tun::AgentHello,
    ) -> anyhow::Result<()> {
        let token = TunnelToken(hello.token);
        match hello.intent {
            tun::Intent::Listen => {
                self.tunnels.register_listener(token, connection).await?;
            }
            tun::Intent::Connect => {
                let Some(session) = hello.session else {
                    anyhow::bail!("tunnel connect missing session token");
                };
                self.tunnels
                    .accept_connect(token, SessionToken(session), connection)
                    .await?;
            }
        }
        Ok(())
    }

    async fn read_ingress_hello(
        &self,
        connection: &mut crate::sock::Connection,
    ) -> anyhow::Result<IngressHello> {
        let mut buf = Vec::new();
        let mut read_buf = vec![0u8; 1024];
        loop {
            let (n, next) = connection.read_chunk(read_buf).await?;
            read_buf = next;
            if n == 0 {
                anyhow::bail!("unexpected eof while reading hello");
            }
            buf.extend_from_slice(&read_buf[..n]);
            if buf.len() < 4 {
                continue;
            }
            break;
        }

        if buf.starts_with(&tun::MAGIC) {
            let hello = self.read_tunnel_hello(connection, buf).await?;
            return Ok(IngressHello::Tunnel { hello });
        }

        let mut decoder = PacketDecoder::new();
        decoder.queue_slice(&buf);
        loop {
            if let Some(frame) = decoder.try_next_packet()? {
                let handshake = decode_handshake_frame(&frame)?;
                let mut raw = Vec::new();
                encode_raw_packet(&mut raw, frame.id, &frame.body)?;
                let pending = decoder.take_pending_bytes();
                return Ok(IngressHello::Minecraft {
                    handshake: OwnedHandshake::from_packet(handshake),
                    buffered: pending,
                    raw,
                });
            }
            let (n, next) = connection.read_chunk(read_buf).await?;
            read_buf = next;
            if n == 0 {
                return Err(anyhow::anyhow!("unexpected eof while reading handshake"));
            }
            decoder.queue_slice(&read_buf[..n]);
        }
    }

    async fn read_tunnel_hello(
        &self,
        connection: &mut crate::sock::Connection,
        mut buf: Vec<u8>,
    ) -> anyhow::Result<tun::AgentHello> {
        loop {
            match tun::decode_agent_hello(&buf)? {
                Some((hello, _consumed)) => return Ok(hello),
                None => {
                    let mut read_buf = vec![0u8; 1024];
                    let (n, next) = connection.read_chunk(read_buf).await?;
                    read_buf = next;
                    if n == 0 {
                        anyhow::bail!("unexpected eof while reading tunnel hello");
                    }
                    buf.extend_from_slice(&read_buf[..n]);
                }
            }
        }
    }

    async fn handle_proxy_session(
        &self,
        mut client: EncodedConnection<'_>,
        handshake: &OwnedHandshake,
        route: &Route,
        session: &Session,
        login_raw: &[u8],
    ) -> anyhow::Result<()> {
        let config = self.config_snapshot().await;
        let server_address = session.destination_addr;
        let client_addr = session.client_addr;
        let hostname = handshake.server_address.as_ref();

        let mut owned_stream = match backend::connect(
            server_address,
            handshake,
            Some(session.endpoint_host.as_str()),
            server_address.port(),
            route.preserve_host(),
            route.proxied(),
            &config,
            client_addr,
        )
        .await
        {
            Ok(stream) => stream,
            Err(backend::BackendConnectError::Connect(err)) => {
                let err = self
                    .disconnect_backend_error(
                        &mut client,
                        client_addr,
                        server_address,
                        hostname,
                        "connection",
                        err,
                    )
                    .await?;
                return Err(err.into());
            }
            Err(backend::BackendConnectError::Handshake(err)) => {
                let err = self
                    .disconnect_backend_error(
                        &mut client,
                        client_addr,
                        server_address,
                        hostname,
                        "handshake",
                        err,
                    )
                    .await?;
                return Err(err.into());
            }
        };
        let mut server = EncodedConnection::new(&mut owned_stream, SocketIntent::GreetToBackend);
        server.send_raw(login_raw).await?;

        let pending = client.take_pending_inbound();
        if !pending.is_empty() {
            server.send_raw(&pending).await?;
        }

        passthrough_now(&mut client, &mut server, session).await?;
        Ok(())
    }

    async fn status_error(
        &self,
        client: &mut EncodedConnection<'_>,
        config: &LureConfig,
    ) -> anyhow::Result<()> {
        self.metrics.record_failure("status");
        query::send_status_failure(client, config, "ERROR").await
    }

    async fn disconnect_login<F, S, L>(
        &self,
        client: &mut EncodedConnection<'_>,
        address: SocketAddr,
        make_reason: F,
    ) where
        F: FnOnce(&LureConfig) -> (S, L),
        S: AsRef<str>,
        L: AsRef<str>,
    {
        let config = self.config_snapshot().await;
        let (public_reason, log_reason) = make_reason(&config);
        self.metrics.record_failure("login");
        if let Err(err) = self
            .errors
            .disconnect_with_log(client, address, || (public_reason, log_reason))
            .await
        {
            LureLogger::disconnect_failure(&address, &err);
        }
    }

    async fn create_proxy_session(
        &self,
        client: &mut EncodedConnection<'_>,
        address: SocketAddr,
        hostname: &str,
        resolved: &ResolvedRoute,
        profile: Arc<Profile>,
    ) -> Option<(SessionHandle, Arc<Route>)> {
        let session_result = timeout(
            Duration::from_secs(1),
            self.router
                .create_session_with_resolved(resolved, address, hostname, profile),
        )
        .await;

        match session_result {
            Ok(Ok((session, route))) => Some((session, route)),
            Ok(Err(e)) => {
                LureLogger::session_creation_failed(&address, hostname, &e);
                self.disconnect_login(client, address, |config| {
                    (
                        config.string_value("ERROR"),
                        format!("ERROR: session creation failed for host '{hostname}': {e}"),
                    )
                })
                .await;
                None
            }
            Err(_) => {
                LureLogger::deadline_missed(
                    "router.create_session",
                    Duration::from_secs(1),
                    Some(&address),
                    Some(hostname),
                );
                LureLogger::session_creation_timeout(&address, hostname);
                self.disconnect_login(client, address, |config| {
                    (
                        config.string_value("ERROR"),
                        format!("ERROR: session creation timed out for host '{hostname}'"),
                    )
                })
                .await;
                None
            }
        }
    }

    async fn disconnect_backend_error(
        &self,
        client: &mut EncodedConnection<'_>,
        client_addr: SocketAddr,
        server_address: SocketAddr,
        hostname: &str,
        stage: &str,
        err: anyhow::Error,
    ) -> anyhow::Result<ReportableError> {
        let config = self.config_snapshot().await;
        let err = ReportableError::from(err);
        let key = "MESSAGE_CANNOT_CONNECT";
        self.errors
            .disconnect_with_log(client, client_addr, || {
                (
                    config.string_value(key),
                    format!(
                        "{key}: backend {stage} to {server_address} for host '{hostname}': {err}"
                    ),
                )
            })
            .await?;
        Ok(err)
    }
}

fn decode_handshake_frame<'a>(
    frame: &'a net::PacketFrame,
) -> anyhow::Result<HandshakeC2s<'a>> {
    if frame.id != HandshakeC2s::ID {
        return Err(anyhow::anyhow!(
            "unexpected packet id {} (expected {})",
            frame.id,
            HandshakeC2s::ID
        ));
    }
    let mut body = frame.body.as_slice();
    let pkt = HandshakeC2s::decode_body(&mut body)?;
    if !body.is_empty() {
        return Err(ProtoError::TrailingBytes(body.len()).into());
    }
    Ok(pkt)
}

enum IngressHello {
    Minecraft {
        handshake: OwnedHandshake,
        buffered: Vec<u8>,
        raw: Vec<u8>,
    },
    Tunnel {
        hello: tun::AgentHello,
    },
}
