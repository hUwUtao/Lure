use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::FutureExt;
use log::{debug, info};
use net::{
    HandshakeC2s, HandshakeNextState, StatusPingC2s, StatusPongS2c, StatusRequestC2s,
    StatusResponseS2c,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{RwLock, Semaphore},
    task::yield_now,
    time::{error::Elapsed, timeout},
};

use crate::{
    config::LureConfig,
    connection::{EncodedConnection, SocketIntent, passthrough_now},
    error::{ErrorResponder, ReportableError},
    logging::LureLogger,
    metrics::HandshakeMetrics,
    packet::{OwnedHandshake, OwnedLoginStart, OwnedPacket},
    router::{Profile, ResolvedRoute, Route, RouterInstance, Session, SessionHandle},
    telemetry::{EventEnvelope, EventServiceInstance, event::EventHook, get_meter, init_event},
    threat::{
        ClientFail, ClientIntent, IntentTag, ThreatControlService, ratelimit::RateLimiterController,
    },
    utils::{Connection, OwnedStatic, leak, spawn_named},
};
mod backend;
mod query;
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

    async fn handle_connection(
        &self,
        client_socket: Connection,
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        LureLogger::new_connection(&address);

        self.handle_handshake(client_socket).await?;
        Ok(())
    }

    async fn handle_handshake(&self, mut connection: Connection) -> anyhow::Result<()> {
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
                        .map(|f| f.map(OwnedHandshake::from_packet))
                        .await
                },
                HANDSHAKE_INTENT,
            )
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
            (OwnedLoginStart::from_packet(login_frame.packet), login_frame.raw)
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
        let _ = self
            .handle_proxy_session(client, handshake, route.as_ref(), &session, &login_raw)
            .await
            .map_err(|e| {
                let re = ReportableError::from(e);
                LureLogger::connection_error(&address, Some(&server_address), &re);
                re
            });

        Ok(())
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
