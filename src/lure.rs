use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::bail;
use async_trait::async_trait;
use bytes::BytesMut;
use futures::FutureExt;
use log::{debug, error, info, warn};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    KeyValue,
};
use serde::{Deserialize, Serialize};
use thiserror::__private::AsDynError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{broadcast, Semaphore},
    task::yield_now,
    time::timeout,
};
use valence_protocol::{
    packets::{
        handshaking::{handshake_c2s::HandshakeNextState, HandshakeC2s},
        status::{QueryPingC2s, QueryPongS2c, QueryRequestC2s, QueryResponseS2c},
    },
    PacketDecoder,
};
use valence_text::{Color, IntoText};

use crate::{
    config::LureConfig,
    connection::{EncodedConnection, SocketIntent},
    error::ReportableError,
    packet::{create_proxy_protocol_header, OwnedHandshake, OwnedPacket},
    router::{HandshakeOption, ResolvedRoute, RouterInstance, Session},
    telemetry::{event::EventHook, get_meter, init_event, EventEnvelope, EventServiceInstance},
    threat::{ratelimit::RateLimiterController, ClientIntent, IntentTag, ThreatControlService},
    utils::{leak, placeholder_status_response, Connection, OwnedStatic},
};

struct HandshakeMetrics {
    attempts: Counter<u64>,
    failures: Counter<u64>,
    duration: Histogram<u64>,
}

impl HandshakeMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            attempts: meter.u64_counter("lure_handshake_total").build(),
            failures: meter.u64_counter("lure_handshake_fail_total").build(),
            duration: meter.u64_histogram("lure_handshake_time_ms").build(),
        }
    }
}

pub struct Lure {
    config: LureConfig,
    router: &'static RouterInstance,
    threat: &'static ThreatControlService,
    metrics: HandshakeMetrics,
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
        }
    }

    async fn peek_handshake(stream: &tokio::net::TcpStream) -> anyhow::Result<OwnedHandshake> {
        let mut buf = [0u8; 1024];
        let mut decoder = PacketDecoder::new();
        let mut filled = 0;
        loop {
            let n = stream.peek(&mut buf).await?;
            if n > filled {
                decoder.queue_bytes(BytesMut::from(&buf[filled..n]));
                filled = n;
            }
            if let Some(frame) = decoder.try_next_packet()? {
                let hs: HandshakeC2s = frame.decode()?;
                return Ok(OwnedHandshake::from_packet(hs));
            }
            if n == buf.len() {
                bail!("handshake too large");
            }
            yield_now().await;
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

            let client = Connection::new(client, addr);

            // Apply IP-based rate limiting
            let ip = addr.ip();
            if let crate::threat::ratelimit::RateLimitResult::Disallowed { retry_after: _ra } =
                rate_limiter.check(&ip)
            {
                debug!("Rate-limited {ip}");
                drop(client);
                continue;
            }

            // Try to acquire semaphore (non-blocking)
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    if dotenvy::var("NO_NODELAY").is_err() {
                        if let Err(e) = client.as_ref().set_nodelay(true) {
                            error!("Failed to set TCP_NODELAY: {e}");
                        }
                    }

                    let lure = self;
                    tokio::spawn(async move {
                        // Apply timeout to connection handling
                        if let Err(e) = lure.handle_connection(client, addr).await {
                            debug!("Connection {addr} closed: {e}")
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
    fn connection_error_log<T>(client: &SocketAddr, server: Option<&SocketAddr>, err: &T)
    where
        T: std::error::Error,
    {
        if dotenvy::var("DO_NOT_LOG_CONNECTION_ERROR").is_ok() {
            return;
        }
        let server_str = server.map(|s| format!(" -> {s}")).unwrap_or_default();
        error!("connection error@{client}{server_str}: {}", err);
    }

    pub async fn handle_connection(
        &self,
        client_socket: Connection,
        address: SocketAddr,
    ) -> anyhow::Result<()> {
        // Client state
        info!("New connection {}", address);

        self.handle_handshake(client_socket).await?;
        Ok(())
    }

    pub async fn handle_handshake(&self, mut connection: Connection) -> anyhow::Result<()> {
        let start = Instant::now();
        let hs = timeout(
            Duration::from_secs(5),
            Self::peek_handshake(connection.as_ref()),
        )
        .await??;
        let state_attr = match hs.next_state {
            HandshakeNextState::Status => "status",
            HandshakeNextState::Login => "login",
        };
        self.metrics
            .attempts
            .add(1, &[KeyValue::new("state", state_attr)]);

        let mut handler = EncodedConnection::new(&mut connection, SocketIntent::GreetToProxy);
        const INTENT: ClientIntent = ClientIntent {
            tag: IntentTag::Handshake,
            duration: Duration::from_secs(60),
        };
        let elapsed_ms = start.elapsed().as_millis() as u64;
        debug!("Handshake completed in {}ms", elapsed_ms);
        self.metrics
            .duration
            .record(elapsed_ms, &[KeyValue::new("state", state_attr)]);

        let resolved = match timeout(
            Duration::from_secs(1),
            self.router.resolve(&hs.server_address),
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(_) => None,
        };

        match hs.next_state {
            HandshakeNextState::Status => self.handle_status(handler, &hs, resolved).await,
            HandshakeNextState::Login => self.handle_proxy(handler, &hs, resolved).await,
        }
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

    async fn disconnect_with_log<S, L>(
        &self,
        client: &mut EncodedConnection<'_>,
        addr: SocketAddr,
        public_reason: S,
        log_reason: L,
    ) -> anyhow::Result<()>
    where
        S: Into<String>,
        L: Into<String>,
    {
        let public_reason = public_reason.into();
        let log_reason = log_reason.into();
        warn!("Disconnecting client {addr}: {log_reason}");
        client
            .disconnect_player(public_reason.into_text().color(Color::RED))
            .await
    }

    async fn disconnect_with_error(
        &self,
        client: &mut EncodedConnection<'_>,
        addr: SocketAddr,
        err: &ReportableError,
        context: impl Into<String>,
    ) -> anyhow::Result<()> {
        let context = context.into();
        let err_msg = err.to_string();
        let public_reason = format!("Gateway error:\n\n{}", err_msg);
        let log_reason = format!("{}: {}", context, err_msg);
        self.disconnect_with_log(client, addr, public_reason, log_reason)
            .await
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
        let Some(resolved) = resolved else {
            self.metrics
                .failures
                .add(1, &[KeyValue::new("state", "status")]);
            self.send_status_failure(&mut client, "ROUTE_NOT_FOUND")
                .await?;
            return Ok(());
        };

        let mut backend = match self.open_backend_connection(resolved.endpoint).await {
            Ok(connection) => connection,
            Err(_) => {
                self.metrics
                    .failures
                    .add(1, &[KeyValue::new("state", "status")]);
                self.send_status_failure(&mut client, "SERVER_OFFLINE")
                    .await?;
                return Ok(());
            }
        };

        let client_addr = *client.as_inner().addr();
        let mut server = EncodedConnection::new(&mut backend, SocketIntent::GreetToBackend);

        let hs = client.recv::<HandshakeC2s>().await?;
        server.send(&hs).await?;

        if let Err(_) = self
            .initialize_backend_protocol(
                &mut server,
                &resolved.route.handshake,
                client_addr,
                handshake,
            )
            .await
        {
            self.metrics
                .failures
                .add(1, &[KeyValue::new("state", "status")]);
            self.send_status_failure(&mut client, "SERVER_OFFLINE")
                .await?;
            return Ok(());
        }

        let req = self
            .threat
            .nuisance(client.recv::<QueryRequestC2s>(), INTENT)
            .await??;
        server.send(&req).await?;

        let response = match server.recv::<QueryResponseS2c>().await {
            Ok(r) => r,
            Err(_) => {
                self.metrics
                    .failures
                    .add(1, &[KeyValue::new("state", "status")]);
                self.send_status_failure(&mut client, "SERVER_OFFLINE")
                    .await?;
                return Ok(());
            }
        };
        client.send(&response).await?;

        let ping = self
            .threat
            .nuisance(client.recv::<QueryPingC2s>(), INTENT)
            .await??;
        server.send(&ping).await?;
        match server.recv::<QueryPongS2c>().await {
            Ok(pong) => client.send(&pong).await?,
            Err(_) => {
                self.metrics
                    .failures
                    .add(1, &[KeyValue::new("state", "status")]);
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
            self.metrics
                .failures
                .add(1, &[KeyValue::new("state", "login")]);
            let display = format!("Route not found for {hostname}");
            let log_reason = format!("route '{hostname}' not found");
            if let Err(err) = self
                .disconnect_with_log(&mut client, address, display, log_reason)
                .await
            {
                debug!("Failed to send disconnect to {address}: {err}");
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
                        handshake, // &login,
                        &route.handshake,
                        &session,
                    )
                    .await
                {
                    let re = ReportableError::from(e);
                    Self::connection_error_log(&address, Some(&server_address), &re);
                }
            }
            Ok(Err(e)) => {
                debug!("Failed to create session for {address} (host '{hostname}'): {e}");
                self.metrics
                    .failures
                    .add(1, &[KeyValue::new("state", "login")]);
                let display = format!("Failed to create session for {hostname}");
                let log_reason = format!("session creation failed for host '{hostname}': {e}");
                if let Err(err) = self
                    .disconnect_with_log(&mut client, address, display, log_reason)
                    .await
                {
                    debug!("Failed to send disconnect to {address}: {err}");
                }
            }
            Err(_) => {
                debug!("Session creation timed out for {address} (host '{hostname}')");
                self.metrics
                    .failures
                    .add(1, &[KeyValue::new("state", "login")]);
                let display = format!("Session creation timed out for {hostname}");
                let log_reason = format!("session creation timed out for host '{hostname}'");
                if let Err(err) = self
                    .disconnect_with_log(&mut client, address, display, log_reason)
                    .await
                {
                    debug!("Failed to send disconnect to {address}: {err}");
                }
            }
        }
        Ok(())
    }

    pub async fn handle_proxy_session(
        &self,
        mut client: EncodedConnection<'_>,
        handshake: &OwnedHandshake,
        // login: &OwnedLoginHello,
        handshake_option: &HandshakeOption,
        session: &Session,
    ) -> anyhow::Result<()> {
        let server_address = session.destination_addr;
        let client_addr = *client.as_inner().addr();
        let hostname = handshake.server_address.as_str();

        let mut owned_stream = match self.open_backend_connection(server_address).await {
            Ok(stream) => stream,
            Err(err) => {
                let err = ReportableError::from(err);
                self.disconnect_with_error(
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
            .initialize_backend_protocol(&mut server, handshake_option, client_addr, handshake)
            .await
        {
            let err = ReportableError::from(err);
            self.disconnect_with_error(
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
                error!("Failed to set TCP_NODELAY: {e}");
            }
        }

        Connection::try_from(stream)
    }

    async fn initialize_backend_protocol(
        &self,
        server: &mut EncodedConnection<'_>,
        handshake_option: &HandshakeOption,
        client_addr: SocketAddr,
        handshake: &OwnedHandshake,
    ) -> anyhow::Result<()> {
        if let HandshakeOption::HAProxy = handshake_option {
            let pkt = create_proxy_protocol_header(client_addr)?;
            timeout(Duration::from_secs(1), server.send_raw(&pkt)).await??;
        }

        timeout(Duration::from_secs(1), server.send(&handshake.as_packet())).await??;
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

        // Borrowed from mqudsi/tcpproxy
        // https://github.com/mqudsi/tcpproxy/blob/e2d423b72898b497b129e8a58307934f9335974b/src/main.rs#L114C1-L159C6
        // Quote
        // Two instances of this function are spawned for each half of the connection: client-to-server,
        // server-to-client. We can't use tokio::io::copy() instead (no matter how convenient it might
        // be) because it doesn't give us a way to correlate the lifetimes of the two tcp read/write
        // loops: even after the client disconnects, tokio would keep the upstream connection to the
        // server alive until the connection's max client idle timeout is reached.
        // Unquote
        async fn copy_with_abort<R, W, L>(
            read: &mut R,
            write: &mut W,
            mut abort: broadcast::Receiver<()>,
            poll_size: L,
        ) -> anyhow::Result<()>
        where
            R: tokio::io::AsyncRead + Unpin,
            W: tokio::io::AsyncWrite + Unpin,
            L: Fn(u64),
        {
            // let mut copied = 0;
            let mut buf = [0u8; 1024];
            loop {
                let bytes_read;
                tokio::select! {
                    res = read.read(&mut buf) => {
                        bytes_read = match res {
                            Ok(n) => n,
                            Err(e) => match e.kind() {
                                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => 0,
                                _ => return Err(ReportableError::from(e).into()),
                            },
                        };
                        poll_size(bytes_read as u64);
                    },
                    _ = abort.recv() => {
                        break;
                    }
                }
                if bytes_read == 0 {
                    break;
                }
                // While we ignore some read errors above, any error writing data we've already read to
                // the other side is always treated as exceptional.
                write.write_all(&buf[0..bytes_read]).await?;
                write.flush().await?;
                // copied += bytes_read;
            }
            Ok(())
            // Ok(copied)
        }

        let (cancel, _) = broadcast::channel::<()>(1);
        // how would two error can be reported consecutively under single handler? maybe we do it byo.
        let (ra, rb) = tokio::join! {
            copy_with_abort(&mut remote_read, &mut client_write, cancel.subscribe(), move |u| {
                vr1.add(u, &[s2c.clone()]);
                pr1.add(1, &[s2c.clone()]);
            })
                .then(|r| { let _ = cancel.send(()); async { r } }),
            copy_with_abort(&mut client_read, &mut remote_write, cancel.subscribe(),
                move |u| {
                    vr2.add(u, &[c2s.clone()]);
                    pr2.add(1, &[c2s.clone()]);
                }
            )
                .then(|r| { let _ = cancel.send(()); async { r } }),
        };

        if let Err(era) = ra {
            Self::connection_error_log(&cad, Some(&rad), &era.as_dyn_error())
        }
        if let Err(erb) = rb {
            Self::connection_error_log(&cad, Some(&rad), &erb.as_dyn_error())
        }

        Ok(())
    }
}
