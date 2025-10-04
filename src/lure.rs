use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
    sync::{broadcast, Semaphore},
    time::{error::Elapsed, timeout},
};
use valence_protocol::{
    packets::{
        handshaking::{handshake_c2s::HandshakeNextState, HandshakeC2s},
        status::{QueryPingC2s, QueryPongS2c, QueryRequestC2s, QueryResponseS2c},
    },
    var_int::{VarInt, VarIntDecodeError},
    Decode, Packet,
};

use crate::{
    config::LureConfig,
    connection::{copy_with_abort, EncodedConnection, SocketIntent},
    error::{ErrorResponder, ReportableError},
    logging::LureLogger,
    metrics::HandshakeMetrics,
    packet::{create_proxy_protocol_header, OwnedHandshake, OwnedPacket},
    router::{ResolvedRoute, RouterInstance, Session},
    telemetry::{event::EventHook, get_meter, init_event, EventEnvelope, EventServiceInstance},
    threat::{
        ratelimit::RateLimiterController, ClientFail, ClientIntent, IntentTag, ThreatControlService,
    },
    utils::{leak, placeholder_status_response, Connection, OwnedStatic},
};
pub struct Lure {
    config: LureConfig,
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
            config,
            router,
            threat: leak(ThreatControlService::new()),
            metrics: HandshakeMetrics::new(&get_meter()),
            errors: ErrorResponder::new(),
        }
    }

    pub async fn start(&'static self) -> anyhow::Result<()> {
        // Listener config.
        let listener_cfg = self.config.bind.to_owned();
        LureLogger::preparing_socket(&listener_cfg);
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

            let client = Connection::new(client, addr);

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
                    if dotenvy::var("NO_NODELAY").is_err() {
                        if let Err(e) = client.as_ref().set_nodelay(true) {
                            LureLogger::tcp_nodelay_failed(&e);
                        }
                    }

                    let lure = self;
                    tokio::spawn(async move {
                        // Apply timeout to connection handling
                        if let Err(e) = lure.handle_connection(client, addr).await {
                            LureLogger::connection_closed(&addr, &e);
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
            self.router.resolve(&hs.server_address),
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(_) => {
                LureLogger::deadline_missed(
                    "router.resolve",
                    Duration::from_secs(1),
                    Some(&client_addr),
                    Some(hs.server_address.as_str()),
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
            .strings
            .get(key)
            .unwrap_or(&"".into())
            .to_owned()
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

        if let Err(err) = self
            .initialize_backend_protocol(
                &mut server,
                resolved.route.proxied(),
                client_addr,
                handshake,
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
        let hostname = handshake.server_address.as_str();

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
                    .handle_proxy_session(client, handshake, route.proxied(), &session)
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
        session: &Session,
    ) -> anyhow::Result<()> {
        let server_address = session.destination_addr;
        let client_addr = *client.as_inner().addr();
        let hostname = handshake.server_address.as_str();

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

        if let Err(err) = self
            .initialize_backend_protocol(&mut server, proxied, client_addr, handshake)
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

        if dotenvy::var("NO_NODELAY").is_err() {
            if let Err(e) = stream.set_nodelay(true) {
                LureLogger::tcp_nodelay_failed(&e);
            }
        }

        Connection::try_from(stream)
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
        let volume_record = get_meter()
            .u64_counter("lure_proxy_transport_volume")
            .with_unit("bytes")
            .build();
        let vr1 = volume_record.clone();
        let vr2 = volume_record.clone();

        let packet_record = get_meter()
            .u64_counter("lure_proxy_transport_packet_count")
            .with_unit("packets")
            .build();
        let pr1 = packet_record.clone();
        let pr2 = packet_record.clone();

        let s2c = KeyValue::new("intent", "s2c");
        let c2s = KeyValue::new("intent", "c2s");

        let client = client.as_inner_mut();
        let server = server.as_inner_mut();
        let cad = *client.addr();
        let rad = *server.addr();
        let (mut client_read, mut client_write) = client.as_mut().split();
        let (mut remote_read, mut remote_write) = server.as_mut().split();

        let (cancel, _) = broadcast::channel::<()>(1);
        // how would two error can be reported consecutively under single handler? maybe we do it byo.
        let (ra, rb) = tokio::join! {
            copy_with_abort(&mut remote_read, &mut client_write, cancel.subscribe(),
                move |u| {
                    vr1.add(u, std::slice::from_ref(&c2s));
                    pr1.add(1, std::slice::from_ref(&c2s));
                }
            )
                .then(|r| { let _ = cancel.send(()); async { r } }),
            copy_with_abort(&mut client_read, &mut remote_write, cancel.subscribe(),
                move |u| {
                    vr2.add(u, std::slice::from_ref(&s2c));
                    pr2.add(1, std::slice::from_ref(&s2c));
                }
            )
                .then(|r| { let _ = cancel.send(()); async { r } }),
        };

        if let Err(era) = ra {
            LureLogger::connection_error(&cad, Some(&rad), &era);
        }
        if let Err(erb) = rb {
            LureLogger::connection_error(&cad, Some(&rad), &erb);
        }

        Ok(())
    }
}
