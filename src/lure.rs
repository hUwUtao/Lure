use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::FutureExt;
use log::{debug, info};
use net::{
    HandshakeC2s, HandshakeNextState, LoginStartC2s, StatusPingC2s, StatusPongS2c,
    StatusRequestC2s, StatusResponseS2c,
};
use opentelemetry::KeyValue;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{RwLock, Semaphore, broadcast},
    task::yield_now,
    time::{error::Elapsed, timeout},
};

use crate::{
    config::LureConfig,
    connection::{EncodedConnection, SocketIntent, copy_with_abort},
    error::{ErrorResponder, ReportableError},
    logging::LureLogger,
    metrics::HandshakeMetrics,
    packet::{OwnedHandshake, OwnedLoginStart, OwnedPacket, create_proxy_protocol_header},
    router::{Profile, ResolvedRoute, Route, RouterInstance, Session, SessionHandle},
    telemetry::{EventEnvelope, EventServiceInstance, event::EventHook, get_meter, init_event},
    threat::{
        ClientFail, ClientIntent, IntentTag, ThreatControlService, ratelimit::RateLimiterController,
    },
    utils::{Connection, OwnedStatic, leak, placeholder_status_response, spawn_named},
};
pub struct Lure {
    config: RwLock<LureConfig>,
    router: &'static RouterInstance,
    threat: &'static ThreatControlService,
    metrics: HandshakeMetrics,
    errors: ErrorResponder,
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

    /// Builds the backend handshake address, preserving any post-NUL suffixes.
    fn backend_handshake_parts<'a>(
        &self,
        handshake: &'a OwnedHandshake,
        endpoint_host: Option<&str>,
        endpoint_port: u16,
        preserve_host: bool,
    ) -> (Cow<'a, str>, u16) {
        if !preserve_host {
            let mut new_server_address = String::new();
            if let Some(host) = endpoint_host {
                new_server_address.push_str(host);
            }
            if let Some(nul) = handshake.server_address.find('\0') {
                new_server_address.push_str(&handshake.server_address[nul..]);
            }
            return (Cow::Owned(new_server_address), endpoint_port);
        }

        (
            Cow::Borrowed(handshake.server_address.as_ref()),
            handshake.server_port,
        )
    }

    async fn init_backend_handshake(
        &self,
        server: &mut EncodedConnection<'_>,
        handshake: &OwnedHandshake,
        endpoint_host: Option<&str>,
        endpoint_port: u16,
        preserve_host: bool,
        proxied: bool,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        if proxied {
            let pkt = create_proxy_protocol_header(client_addr)?;
            server.send_raw(&pkt).await?;
            debug!("PP Sent");
        }

        let (server_address, server_port) =
            self.backend_handshake_parts(handshake, endpoint_host, endpoint_port, preserve_host);
        let packet = HandshakeC2s {
            protocol_version: handshake.protocol_version,
            server_address: server_address.as_ref(),
            server_port,
            next_state: handshake.next_state,
        };

        server.send(&packet).await?;
        debug!("HS Sent");
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
        let listener = TcpListener::bind(address).await?;
        let semaphore = Arc::new(Semaphore::new(max_connections));
        let rate_limiter: RateLimiterController<IpAddr> = RateLimiterController::new(10, cooldown);

        loop {
            // Accept connection first
            let (client, addr) = listener.accept().await?;

            let client = Connection::new(client, addr);

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
                        && let Err(e) = client.as_ref().set_nodelay(true)
                    {
                        LureLogger::tcp_nodelay_failed(&e);
                    }

                    let lure = self;
                    spawn_named("Connection handler", async move {
                        // Apply timeout to connection handling
                        if let Err(e) = lure.handle_connection(client, addr).await {
                            LureLogger::connection_closed(&addr, &e);
                        }
                        drop(permit);
                    })?;
                }
                Err(_) => {
                    // Too many connections, reject immediately
                    drop(client);
                }
            }
            yield_now().await;
        }
    }

    pub async fn handle_connection(
        &self,
        client_socket: Connection,
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        LureLogger::new_connection(&address);

        self.handle_handshake(client_socket).await?;
        Ok(())
    }

    pub async fn handle_handshake(&self, mut connection: Connection) -> anyhow::Result<()> {
        let start = Instant::now();
        let client_addr = *connection.addr();
        const HANDSHAKE_INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Handshake,
            duration: Duration::from_secs(5),
        };
        let mut handler = EncodedConnection::new(&mut connection, SocketIntent::GreetToProxy);
        let hs = self
            .threat
            .nuisance(
                async {
                    handler
                        .recv::<HandshakeC2s>()
                        .await
                        .map(OwnedHandshake::from_packet)
                },
                HANDSHAKE_INTENT,
            )
            .await
            .map_err(|err| {
                if let Some(ClientFail::Timeout { intent, .. }) = err.downcast_ref::<ClientFail>() {
                    LureLogger::deadline_missed(
                        "client handshake",
                        intent.duration,
                        Some(&client_addr),
                        None,
                    );
                } else {
                    LureLogger::parser_failure(&client_addr, "client handshake", &err);
                }
                err
            })?
            .map_err(|err| {
                LureLogger::parser_failure(&client_addr, "client handshake", &err);
                err
            })?;
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
            HandshakeNextState::Login => self.handle_proxy(handler, &hs, resolved).await,
        }
    }

    async fn get_string(&self, key: &str) -> Box<str> {
        self.config
            .read()
            .await
            .strings
            .get(key)
            .cloned()
            .unwrap_or_else(|| "".into())
    }

    async fn placeholder_status_json(&self, label: &str) -> String {
        let brand = self.get_string("SERVER_LIST_BRAND").await;
        let target_label = self.get_string(label).await;
        placeholder_status_response(brand.as_ref(), target_label.as_ref())
    }

    async fn send_status_failure(
        &self,
        client: &mut EncodedConnection<'_>,
        label: &str,
    ) -> anyhow::Result<()> {
        let placeholder = self.placeholder_status_json(label).await;
        client
            .send(&StatusResponseS2c { json: &placeholder })
            .await?;
        Ok(())
    }

    pub async fn handle_status(
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
        let Some(resolved) = resolved else {
            self.metrics.record_failure("status");
            self.send_status_failure(&mut client, "ROUTE_NOT_FOUND")
                .await?;
            return Ok(());
        };

        let backend_addr = resolved.endpoint;
        let backend_label = backend_addr.to_string();

        let mut backend = match self.open_backend_connection(backend_addr).await {
            Ok(connection) => connection,
            Err(err) => {
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
                self.metrics.record_failure("status");
                self.send_status_failure(&mut client, "SERVER_OFFLINE")
                    .await?;
                return Ok(());
            }
        };

        let mut server = EncodedConnection::new(&mut backend, SocketIntent::GreetToBackend);

        if let Err(err) = self
            .init_backend_handshake(
                &mut server,
                handshake,
                Some(resolved.endpoint_host.as_str()),
                backend_addr.port(),
                resolved.route.preserve_host(),
                resolved.route.proxied(),
                client_addr,
            )
            .await
        {
            if err.downcast_ref::<Elapsed>().is_some() {
                LureLogger::deadline_missed(
                    "backend handshake",
                    Duration::from_secs(1),
                    Some(&client_addr),
                    Some(&backend_label),
                );
            } else {
                LureLogger::backend_failure(Some(&client_addr), backend_addr, "handshake", &err);
            }
            self.metrics.record_failure("status");
            self.send_status_failure(&mut client, "SERVER_OFFLINE")
                .await?;
            return Ok(());
        }

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
                self.metrics.record_failure("status");
                self.send_status_failure(&mut client, "SERVER_OFFLINE")
                    .await?;
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

    pub async fn handle_proxy<'a>(
        &self,
        mut client: EncodedConnection<'a>,
        handshake: &OwnedHandshake,
        resolved: Option<ResolvedRoute>,
    ) -> anyhow::Result<()> {
        const INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Handshake,
            duration: Duration::from_secs(5),
        };

        let login = self
            .threat
            .nuisance(client.recv::<LoginStartC2s>(), INTENT)
            .await??;
        let login = OwnedLoginStart::from_packet(login);
        let profile = Arc::new(Profile {
            name: Arc::clone(&login.username),
            uuid: login.profile_id,
        });

        let address = *client.as_inner().addr();
        let hostname = handshake.get_stripped_hostname();
        let hostname = hostname.as_ref();

        let Some(resolved) = resolved else {
            let display = format!("Route not found for {hostname}");
            let log_reason = format!("route '{hostname}' not found");
            self.disconnect_login(&mut client, address, display, log_reason)
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
        if let Err(e) = self
            .handle_proxy_session(client, handshake, route.as_ref(), &session, &login)
            .await
        {
            let re = ReportableError::from(e);
            LureLogger::connection_error(&address, Some(&server_address), &re);
        }

        Ok(())
    }

    pub async fn handle_proxy_session(
        &self,
        mut client: EncodedConnection<'_>,
        handshake: &OwnedHandshake,
        route: &Route,
        session: &Session,
        login: &OwnedLoginStart,
    ) -> anyhow::Result<()> {
        let server_address = session.destination_addr;
        let client_addr = session.client_addr;
        let hostname = handshake.server_address.as_ref();

        let mut owned_stream = match self.open_backend_connection(server_address).await {
            Ok(stream) => stream,
            Err(err) => {
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
        };
        let mut server = EncodedConnection::new(&mut owned_stream, SocketIntent::GreetToBackend);

        if let Err(err) = self
            .init_backend_handshake(
                &mut server,
                handshake,
                Some(session.endpoint_host.as_str()),
                server_address.port(),
                route.preserve_host(),
                route.proxied(),
                client_addr,
            )
            .await
        {
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
        server.send(&login.as_packet()).await?;

        let pending = client.take_pending_inbound();
        if !pending.is_empty() {
            server.send_raw(&pending).await?;
        }

        self.passthrough_now(&mut client, &mut server, session)
            .await?;
        Ok(())
    }

    async fn disconnect_login(
        &self,
        client: &mut EncodedConnection<'_>,
        address: SocketAddr,
        display: String,
        log_reason: String,
    ) {
        self.metrics.record_failure("login");
        if let Err(err) = self
            .errors
            .disconnect_with_log(client, address, display, log_reason)
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
                let display = format!("Failed to create session for {hostname}");
                let log_reason = format!("session creation failed for host '{hostname}': {e}");
                self.disconnect_login(client, address, display, log_reason)
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
                let display = format!("Session creation timed out for {hostname}");
                let log_reason = format!("session creation timed out for host '{hostname}'");
                self.disconnect_login(client, address, display, log_reason)
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
        let err = ReportableError::from(err);
        self.errors
            .disconnect_with_error(
                client,
                client_addr,
                &err,
                format!("backend {stage} to {server_address} for host '{hostname}'"),
            )
            .await?;
        Ok(err)
    }

    async fn open_backend_connection(&self, address: SocketAddr) -> anyhow::Result<Connection> {
        let stream = timeout(Duration::from_secs(3), TcpStream::connect(address)).await??;
        debug!("Connected to backend: {}", address);

        if dotenvy::var("NO_NODELAY").is_err()
            && let Err(e) = stream.set_nodelay(true)
        {
            LureLogger::tcp_nodelay_failed(&e);
        }

        Ok(Connection::try_from(stream)?)
    }

    async fn passthrough_now<'a, 'b>(
        &self,
        client: &mut EncodedConnection<'a>,
        server: &mut EncodedConnection<'b>,
        session: &Session,
    ) -> anyhow::Result<()> {
        let client = client.as_inner_mut();
        let server = server.as_inner_mut();
        let cad = *client.addr();
        let rad = *server.addr();
        let (mut client_read, mut client_write) = client.as_mut().split();
        let (mut remote_read, mut remote_write) = server.as_mut().split();

        let (cancel, _) = broadcast::channel(1);
        let inspect = session.inspect.clone();

        // Allows lint & fmt
        let (la, lb, lc) = (
            {
                let inspect = inspect.clone();
                copy_with_abort(
                    &mut remote_read,
                    &mut client_write,
                    cancel.subscribe(),
                    move |u| {
                        inspect.record_s2c(u);
                    },
                )
                .then(|r| {
                    let _ = cancel.send(());
                    async { r }
                })
            },
            {
                let inspect = inspect.clone();
                copy_with_abort(
                    &mut client_read,
                    &mut remote_write,
                    cancel.subscribe(),
                    move |u| {
                        inspect.record_c2s(u);
                    },
                )
                .then(|r| {
                    let _ = cancel.send(());
                    async { r }
                })
            },
            // Meter report thread
            {
                let abort = cancel.subscribe();

                async move {
                    let mut interval = tokio::time::interval(Duration::from_millis(100));
                    let volume_record = get_meter()
                        .u64_counter("lure_proxy_transport_volume")
                        .with_unit("bytes")
                        .build();

                    let packet_record = get_meter()
                        .u64_counter("lure_proxy_transport_packet_count")
                        .with_unit("packets")
                        .build();

                    let s2ct = KeyValue::new("intent", "s2c");
                    let c2st = KeyValue::new("intent", "c2s");

                    let mut last = inspect.traffic.snapshot();

                    loop {
                        if !abort.is_empty() {
                            break;
                        }

                        let vr1 = volume_record.clone();
                        let vr2 = volume_record.clone();
                        let pr1 = packet_record.clone();
                        let pr2 = packet_record.clone();

                        let snap = inspect.traffic.snapshot();

                        vr1.add(
                            snap.c2s_bytes - last.c2s_bytes,
                            core::slice::from_ref(&c2st),
                        );
                        vr2.add(
                            snap.s2c_bytes - last.s2c_bytes,
                            core::slice::from_ref(&s2ct),
                        );
                        pr1.add(
                            snap.c2s_chunks - last.c2s_chunks,
                            core::slice::from_ref(&c2st),
                        );
                        pr2.add(
                            snap.s2c_chunks - last.s2c_chunks,
                            core::slice::from_ref(&s2ct),
                        );

                        last = snap;

                        interval.tick().await;
                    }
                }
            },
        );
        let (ra, rb, _rc) = tokio::join!(la, lb, lc);

        if let Err(era) = ra {
            LureLogger::connection_error(&cad, Some(&rad), &era);
        }
        if let Err(erb) = rb {
            LureLogger::connection_error(&cad, Some(&rad), &erb);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_with_addr(addr: &str) -> OwnedHandshake {
        OwnedHandshake {
            protocol_version: 0,
            server_address: Arc::from(addr),
            server_port: 25565,
            next_state: HandshakeNextState::Login,
        }
    }

    #[tokio::test]
    async fn backend_handshake_preserves_suffix_after_first_nul() {
        let lure = Lure::new(LureConfig::default());
        let hs = handshake_with_addr("example.com\0FML2\0");
        let (address, _) = lure.backend_handshake_parts(&hs, Some("backend.local"), 25565, false);
        assert_eq!(address.as_ref(), "backend.local\0FML2\0");

        let hs = handshake_with_addr("example.com\0FORGE\0");
        let (address, _) = lure.backend_handshake_parts(&hs, Some("backend.local"), 25565, false);
        assert_eq!(address.as_ref(), "backend.local\0FORGE\0");
    }

    #[tokio::test]
    async fn backend_handshake_keeps_raw_host_when_preserved() {
        let lure = Lure::new(LureConfig::default());
        let hs = handshake_with_addr("example.com\0FORGE\0");
        let (address, port) = lure.backend_handshake_parts(&hs, Some("backend.local"), 25565, true);
        assert_eq!(address.as_ref(), hs.server_address.as_ref());
        assert_eq!(port, hs.server_port);
    }
}
