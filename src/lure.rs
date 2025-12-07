use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{bail, ensure};
use async_trait::async_trait;
use futures::FutureExt;
use log::{debug, info};
use opentelemetry::KeyValue;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, broadcast},
    task::yield_now,
    time::{error::Elapsed, timeout},
};
use valence_protocol::{
    Decode, Packet,
    packets::{
        handshaking::{HandshakeC2s, handshake_c2s::HandshakeNextState},
        status::{QueryPingC2s, QueryPongS2c, QueryRequestC2s, QueryResponseS2c},
    },
    var_int::{VarInt, VarIntDecodeError},
};

use crate::{
    config::LureConfig,
    connection::{EncodedConnection, SocketIntent, copy_with_abort},
    error::{ErrorResponder, ReportableError},
    logging::LureLogger,
    metrics::HandshakeMetrics,
    packet::{OwnedHandshake, OwnedPacket, create_proxy_protocol_header},
    router::{ResolvedRoute, Route, RouterInstance, Session},
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
        Lure {
            config: RwLock::new(config),
            router,
            threat: leak(ThreatControlService::new()),
            metrics: HandshakeMetrics::new(&get_meter()),
            errors: ErrorResponder::new(),
        }
    }

    fn config_snapshot(&self) -> LureConfig {
        self.config.read().expect("config lock poisoned").clone()
    }

    async fn install_routes(&'static self, routes: Vec<Route>) {
        self.router.clear_routes().await;
        for route in routes {
            self.router.apply_route(route).await;
        }
    }

    pub async fn sync_routes_from_config(&'static self) -> anyhow::Result<()> {
        let snapshot = self.config_snapshot();
        let routes = snapshot.default_routes()?;
        self.install_routes(routes).await;
        Ok(())
    }

    pub async fn reload_config(&'static self, config: LureConfig) -> anyhow::Result<()> {
        let routes = config.default_routes()?;
        self.install_routes(routes).await;
        {
            *self
                .config
                .write()
                .expect("config lock poisoned during reload") = config;
        }
        Ok(())
    }

    fn prepare_backend_handshake(
        &self,
        handshake: &OwnedHandshake,
        endpoint_host: Option<&str>,
        endpoint_port: u16,
        preserve_host: bool,
    ) -> OwnedHandshake {
        let mut prepared = handshake.clone();
        if !preserve_host {
            let mut new_server_address = String::new();
            if let Some(host) = endpoint_host {
                new_server_address.push_str(host);
            }

            // Extract FML postfix from client handshake if present
            // Looking for \0FMLx\0 where x is a digit
            if handshake.server_address.len() >= 6
                && handshake.server_address[handshake.server_address.len() - 6..]
                    .starts_with("\0FML")
                && handshake.server_address.ends_with("\0")
            {
                if let Some(x) = handshake
                    .server_address
                    .chars()
                    .nth(handshake.server_address.len() - 2)
                {
                    if x.is_ascii_digit() {
                        new_server_address.push_str(
                            &handshake.server_address[handshake.server_address.len() - 6..],
                        );
                    }
                }
            }

            prepared.server_address = Arc::from(new_server_address);
            prepared.server_port = endpoint_port;
        }
        prepared
    }

    pub async fn start(&'static self) -> anyhow::Result<()> {
        // Listener config.
        let config = self.config_snapshot();
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
        let hs = match self
            .threat
            .nuisance(
                async { Self::read_owned_handshake(connection.as_mut()).await },
                HANDSHAKE_INTENT,
            )
            .await
        {
            Ok(Ok(hs)) => hs,
            Ok(Err(err)) => {
                LureLogger::parser_failure(&client_addr, "client handshake", &err);
                return Err(err);
            }
            Err(err) => {
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
                return Err(err);
            }
        };
        let state_attr = match hs.next_state {
            HandshakeNextState::Status => "status",
            HandshakeNextState::Login => "login",
        };
        self.metrics.record_attempt(state_attr);

        let handler = EncodedConnection::new(&mut connection, SocketIntent::GreetToProxy);
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

    async fn read_owned_handshake(stream: &mut TcpStream) -> anyhow::Result<OwnedHandshake> {
        let mut len_buf = [0u8; 5];
        let mut len_len = 0usize;

        let packet_len = loop {
            stream
                .read_exact(&mut len_buf[len_len..len_len + 1])
                .await?;
            len_len += 1;
            let mut slice = &len_buf[..len_len];
            match VarInt::decode_partial(&mut slice) {
                Ok(len) => {
                    ensure!(len >= 0, "negative handshake length");
                    break len as usize;
                }
                Err(VarIntDecodeError::Incomplete) => {
                    ensure!(len_len < len_buf.len(), "handshake length varint too long");
                }
                Err(VarIntDecodeError::TooLarge) => {
                    bail!("handshake length varint too large");
                }
            }
        };

        let mut packet_buf = vec![0u8; packet_len];
        stream.read_exact(&mut packet_buf).await?;

        let mut body = &packet_buf[..];
        let packet_id = VarInt::decode(&mut body)?.0;
        ensure!(
            packet_id == HandshakeC2s::ID,
            "unexpected packet id {packet_id} for handshake"
        );

        let handshake_packet = HandshakeC2s::decode(&mut body)?;
        Ok(OwnedHandshake::from_packet(handshake_packet))
    }

    fn get_string(&self, key: &str) -> Box<str> {
        self.config
            .read()
            .expect("config lock poisoned")
            .strings
            .get(key)
            .cloned()
            .unwrap_or_else(|| "".into())
    }

    fn placeholder_status_json(&self, label: &str) -> String {
        let brand = self.get_string("SERVER_LIST_BRAND");
        let target_label = self.get_string(label);
        placeholder_status_response(brand.as_ref(), target_label.as_ref())
    }

    async fn send_status_failure(
        &self,
        client: &mut EncodedConnection<'_>,
        label: &str,
    ) -> anyhow::Result<()> {
        let placeholder = self.placeholder_status_json(label);
        client
            .send(&QueryResponseS2c { json: &placeholder })
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

        let backend_handshake = self.prepare_backend_handshake(
            handshake,
            Some(resolved.endpoint_host.as_str()),
            backend_addr.port(),
            resolved.route.preserve_host(),
        );
        if let Err(err) = self
            .initialize_backend_protocol(
                &mut server,
                resolved.route.proxied(),
                client_addr,
                &backend_handshake,
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
            .nuisance(client.recv::<QueryRequestC2s>(), INTENT)
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

        let response = match server.recv::<QueryResponseS2c>().await {
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
            .nuisance(client.recv::<QueryPingC2s>(), INTENT)
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
        match server.recv::<QueryPongS2c>().await {
            Ok(pong) => client.send(&pong).await?,
            Err(err) => {
                LureLogger::parser_failure(&client_addr, "backend status pong", &err);
                self.metrics.record_failure("status");
                client
                    .send(&QueryPongS2c {
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
        let address = *client.as_inner().addr();
        let hostname = &handshake.server_address;

        let Some(resolved) = resolved else {
            self.metrics.record_failure("login");
            let display = format!("Route not found for {hostname}");
            let log_reason = format!("route '{hostname}' not found");
            if let Err(err) = self
                .errors
                .disconnect_with_log(&mut client, address, display, log_reason)
                .await
            {
                LureLogger::disconnect_failure(&address, &err);
            }
            return Ok(());
        };

        let session_result = timeout(
            Duration::from_secs(1),
            self.router.create_session_with_resolved(&resolved, address),
        )
        .await;

        match session_result {
            Ok(Ok((session, route))) => {
                let server_address = session.destination_addr;
                if let Err(e) = self
                    .handle_proxy_session(
                        client,
                        handshake,
                        route.proxied(),
                        route.preserve_host(),
                        &session,
                    )
                    .await
                {
                    let re = ReportableError::from(e);
                    LureLogger::connection_error(&address, Some(&server_address), &re);
                }
            }
            Ok(Err(e)) => {
                LureLogger::session_creation_failed(&address, hostname, &e);
                self.metrics.record_failure("login");
                let display = format!("Failed to create session for {hostname}");
                let log_reason = format!("session creation failed for host '{hostname}': {e}");
                if let Err(err) = self
                    .errors
                    .disconnect_with_log(&mut client, address, display, log_reason)
                    .await
                {
                    LureLogger::disconnect_failure(&address, &err);
                }
            }
            Err(_) => {
                LureLogger::deadline_missed(
                    "router.create_session",
                    Duration::from_secs(1),
                    Some(&address),
                    Some(hostname),
                );
                LureLogger::session_creation_timeout(&address, hostname);
                self.metrics.record_failure("login");
                let display = format!("Session creation timed out for {hostname}");
                let log_reason = format!("session creation timed out for host '{hostname}'");
                if let Err(err) = self
                    .errors
                    .disconnect_with_log(&mut client, address, display, log_reason)
                    .await
                {
                    LureLogger::disconnect_failure(&address, &err);
                }
            }
        }
        Ok(())
    }

    pub async fn handle_proxy_session(
        &self,
        mut client: EncodedConnection<'_>,
        handshake: &OwnedHandshake,
        proxied: bool,
        preserve_host: bool,
        session: &Session,
    ) -> anyhow::Result<()> {
        let server_address = session.destination_addr;
        let client_addr = *client.as_inner().addr();
        let hostname = &handshake.server_address;

        let mut owned_stream = match self.open_backend_connection(server_address).await {
            Ok(stream) => stream,
            Err(err) => {
                let err = ReportableError::from(err);
                self.errors
                    .disconnect_with_error(
                        &mut client,
                        client_addr,
                        &err,
                        format!("backend connection to {server_address} for host '{hostname}'"),
                    )
                    .await?;
                return Err(err.into());
            }
        };
        let mut server = EncodedConnection::new(&mut owned_stream, SocketIntent::GreetToBackend);

        let backend_handshake = self.prepare_backend_handshake(
            handshake,
            Some(session.endpoint_host.as_str()),
            server_address.port(),
            preserve_host,
        );
        if let Err(err) = self
            .initialize_backend_protocol(&mut server, proxied, client_addr, &backend_handshake)
            .await
        {
            let err = ReportableError::from(err);
            self.errors
                .disconnect_with_error(
                    &mut client,
                    client_addr,
                    &err,
                    format!("backend handshake to {server_address} for host '{hostname}'"),
                )
                .await?;
            return Err(err.into());
        }

        self.passthrough_now(&mut client, &mut server).await?;
        Ok(())
    }

    async fn open_backend_connection(&self, address: SocketAddr) -> anyhow::Result<Connection> {
        let stream = timeout(Duration::from_secs(3), TcpStream::connect(address)).await??;

        if dotenvy::var("NO_NODELAY").is_err()
            && let Err(e) = stream.set_nodelay(true)
        {
            LureLogger::tcp_nodelay_failed(&e);
        }

        Ok(Connection::try_from(stream)?)
    }

    async fn initialize_backend_protocol(
        &self,
        server: &mut EncodedConnection<'_>,
        proxied: bool,
        client_addr: SocketAddr,
        handshake: &OwnedHandshake,
    ) -> anyhow::Result<()> {
        if proxied {
            let pkt = create_proxy_protocol_header(client_addr)?;
            server.send_raw(&pkt).await?;
        }

        server.send(&handshake.as_packet()).await?;
        Ok(())
    }

    async fn passthrough_now<'a, 'b>(
        &self,
        client: &mut EncodedConnection<'a>,
        server: &mut EncodedConnection<'b>,
    ) -> anyhow::Result<()> {
        // Put all AtomicU64 in a fixed array so they are not moved.
        // [0] = s2cp, [1] = c2sp, [2] = s2cb, [3] = c2sb
        let counters: [AtomicU64; 4] = [
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ];

        let client = client.as_inner_mut();
        let server = server.as_inner_mut();
        let cad = *client.addr();
        let rad = *server.addr();
        let (mut client_read, mut client_write) = client.as_mut().split();
        let (mut remote_read, mut remote_write) = server.as_mut().split();

        let (cancel, _) = broadcast::channel(1);

        // Allows lint & fmt
        let (la, lb, lc) = (
            {
                let c2sp = &counters[1];
                let c2sb = &counters[3];
                copy_with_abort(
                    &mut remote_read,
                    &mut client_write,
                    cancel.subscribe(),
                    move |u| {
                        c2sp.fetch_add(1, Ordering::Relaxed);
                        c2sb.fetch_add(u, Ordering::Relaxed);
                    },
                )
                .then(|r| {
                    let _ = cancel.send(());
                    async { r }
                })
            },
            {
                let s2cp = &counters[0];
                let s2cb = &counters[2];
                copy_with_abort(
                    &mut client_read,
                    &mut remote_write,
                    cancel.subscribe(),
                    move |u| {
                        s2cp.fetch_add(1, Ordering::Relaxed);
                        s2cb.fetch_add(u, Ordering::Relaxed);
                    },
                )
                .then(|r| {
                    let _ = cancel.send(());
                    async { r }
                })
            },
            // Meter report thread
            {
                let counters = &counters;
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

                    let mut ls2cp = 0u64;
                    let mut ls2cb = 0u64;
                    let mut lc2sp = 0u64;
                    let mut lc2sb = 0u64;

                    loop {
                        if !abort.is_empty() {
                            break;
                        }

                        let vr1 = volume_record.clone();
                        let vr2 = volume_record.clone();
                        let pr1 = packet_record.clone();
                        let pr2 = packet_record.clone();

                        let c2sb = counters[3].load(Ordering::Relaxed);
                        let s2cb = counters[2].load(Ordering::Relaxed);
                        let c2sp = counters[1].load(Ordering::Relaxed);
                        let s2cp = counters[0].load(Ordering::Relaxed);

                        vr1.add(c2sb - lc2sb, core::slice::from_ref(&c2st));
                        vr2.add(s2cb - ls2cb, core::slice::from_ref(&s2ct));
                        pr1.add(c2sp - lc2sp, core::slice::from_ref(&c2st));
                        pr2.add(s2cp - ls2cp, core::slice::from_ref(&s2ct));

                        lc2sb = c2sb;
                        ls2cb = s2cb;
                        lc2sp = c2sp;
                        ls2cp = s2cp;

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
