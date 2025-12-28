use std::{
    fmt::Debug,
    io::{self, ErrorKind},
    time::Duration,
};

use futures::FutureExt;
// use futures::FutureExt;
use net::{
    LoginDisconnectS2c, LoginStartC2s, PacketDecode, PacketDecoder, PacketEncode, PacketEncoder,
    PacketFrame, ProtoError,
};
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter},
};
use serde_json::to_string as json_string;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};

use crate::{
    error::ReportableError, logging::LureLogger, router::Session, telemetry::get_meter,
    utils::Connection,
};

pub(crate) struct EncodedConnection<'a> {
    enc: PacketEncoder,
    dec: PacketDecoder,
    frame: PacketFrame,
    stream: &'a mut Connection,
    metric: ConnectionMetric,
    intent: KeyValue,
    _reserved_lifetime: std::marker::PhantomData<&'a ()>,
}

pub enum SocketIntent {
    GreetToProxy,
    GreetToBackend,
}

impl SocketIntent {
    fn as_attr(&self) -> KeyValue {
        // recv+pipe/send
        let a = match self {
            Self::GreetToProxy => "frontbound",
            Self::GreetToBackend => "backbound",
        };
        KeyValue::new("intent", a)
    }
}

struct ConnectionMetric {
    packet_count: Counter<u64>,
    packet_size: Histogram<u64>,
}

impl ConnectionMetric {
    fn new(metric: &Meter) -> Self {
        Self {
            packet_count: metric.u64_counter("lure_proxy_packet_count").build(),
            packet_size: metric.u64_histogram("lure_proxy_packet_size").build(),
        }
    }
}

const MAX_CHUNK_SIZE: usize = 1024;

struct VersionedLoginStart<'a, 'b> {
    packet: &'a LoginStartC2s<'b>,
    protocol_version: i32,
}

impl<'a, 'b> PacketEncode for VersionedLoginStart<'a, 'b> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> net::mc::Result<()> {
        self.packet
            .encode_body_with_version(out, self.protocol_version)
    }
}

impl<'a> EncodedConnection<'a> {
    pub fn new(stream: &'a mut Connection, intent: SocketIntent) -> Self {
        let metric = get_meter();
        Self {
            enc: PacketEncoder::new(),
            dec: PacketDecoder::new(),
            stream,
            frame: PacketFrame {
                id: 0,
                body: Vec::new(),
            },
            metric: ConnectionMetric::new(&metric),
            intent: intent.as_attr(),
            _reserved_lifetime: std::marker::PhantomData,
        }
    }

    fn packet_record(&self, size: usize) {
        self.metric
            .packet_count
            .add(1, std::slice::from_ref(&self.intent));
        self.metric
            .packet_size
            .record(size as u64, std::slice::from_ref(&self.intent));
    }

    // pub fn enable_encryption(&mut self, key: &[u8; 16]) {
    //     self.enc.enable_encryption(key);
    //     self.dec.enable_encryption(key);
    // }

    pub async fn disconnect_player(&mut self, reason: &str) -> anyhow::Result<()> {
        let reason_json = json_string(reason)?;
        let kick = LoginDisconnectS2c {
            reason: &reason_json,
        };
        self.send(&kick).await?;
        self.drain_pending_inbound();
        let _ = self.stream.as_mut().shutdown().await;
        Ok(())
    }

    fn drain_pending_inbound(&mut self) {
        let mut buf = [0u8; 1024];
        let mut drained = 0usize;
        loop {
            match self.stream.as_mut().try_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    drained = drained.saturating_add(n);
                    if drained >= 64 * 1024 {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    /// Packet recv.
    pub async fn recv<'b, P>(&'b mut self) -> anyhow::Result<P>
    where
        P: PacketDecode<'b> + Debug,
    {
        loop {
            if let Some(frame) = self.dec.try_next_packet()? {
                let size = frame.body.len();
                self.frame = frame;
                self.packet_record(size);
                return decode_frame::<P>(&self.frame);
            }

            let mut buf = [0u8; MAX_CHUNK_SIZE];
            let read_len = self.stream.as_mut().read(&mut buf).await?;
            if read_len == 0 {
                return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
            }
            self.dec.queue_slice(&buf[..read_len]);
        }
    }

    pub async fn recv_login_start<'b>(
        &'b mut self,
        protocol_version: i32,
    ) -> anyhow::Result<LoginStartC2s<'b>> {
        loop {
            if let Some(frame) = self.dec.try_next_packet()? {
                let size = frame.body.len();
                self.frame = frame;
                self.packet_record(size);
                return decode_login_start_frame(&self.frame, protocol_version);
            }

            let mut buf = [0u8; MAX_CHUNK_SIZE];
            let read_len = self.stream.as_mut().read(&mut buf).await?;
            if read_len == 0 {
                return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
            }
            self.dec.queue_slice(&buf[..read_len]);
        }
    }

    pub async fn send<P>(&mut self, pkt: &P) -> anyhow::Result<()>
    where
        P: PacketEncode,
    {
        self.enc.write_packet(pkt)?;
        let bytes = self.enc.take();
        let size = bytes.len();
        self.packet_record(size);
        // timeout(Duration::from_millis(5000), self.write.write_all(&bytes)).await??;
        self.stream.as_mut().write_all(&bytes).await?;
        self.flush().await?;
        Ok(())
    }

    pub async fn send_login_start(
        &mut self,
        pkt: &LoginStartC2s<'_>,
        protocol_version: i32,
    ) -> anyhow::Result<()> {
        let versioned = VersionedLoginStart {
            packet: pkt,
            protocol_version,
        };
        self.enc.write_packet(&versioned)?;
        let bytes = self.enc.take();
        let size = bytes.len();
        self.packet_record(size);
        self.stream.as_mut().write_all(&bytes).await?;
        self.flush().await?;
        Ok(())
    }

    pub async fn send_raw(&mut self, pkt: &[u8]) -> anyhow::Result<()> {
        let size = pkt.len();
        self.packet_record(size);
        self.stream.as_mut().write_all(pkt).await?;
        self.flush().await?;
        Ok(())
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        self.stream.as_mut().flush().await?;
        Ok(())
    }

    pub fn as_inner_mut(&mut self) -> &mut Connection {
        self.stream
    }

    pub fn as_inner(&self) -> &Connection {
        self.stream
    }

    pub fn take_pending_inbound(&mut self) -> Vec<u8> {
        self.dec.take_pending_bytes()
    }
}

fn decode_frame<'a, P>(frame: &'a PacketFrame) -> anyhow::Result<P>
where
    P: PacketDecode<'a> + Debug,
{
    let _ctx = format_args!("type={} id=0x{:02x}", std::any::type_name::<P>(), frame.id);

    if frame.id != P::ID {
        return Err(anyhow::anyhow!(
            "unexpected packet id {} (expected {})",
            frame.id,
            P::ID
        ));
    }

    let mut body = frame.body.as_slice();
    let pkt = match P::decode_body(&mut body) {
        Ok(pkt) => pkt,
        Err(err) => {
            return Err(err.into());
        }
    };
    if !body.is_empty() {
        return Err(ProtoError::TrailingBytes(body.len()).into());
    }
    Ok(pkt)
}

fn decode_login_start_frame<'a>(
    frame: &'a PacketFrame,
    protocol_version: i32,
) -> anyhow::Result<LoginStartC2s<'a>> {
    let _ctx = format_args!(
        "type={} id=0x{:02x}",
        std::any::type_name::<LoginStartC2s<'a>>(),
        frame.id
    );

    if frame.id != LoginStartC2s::ID {
        return Err(anyhow::anyhow!(
            "unexpected packet id {} (expected {})",
            frame.id,
            LoginStartC2s::ID
        ));
    }

    let mut body = frame.body.as_slice();
    let pkt = LoginStartC2s::decode_body_with_version(&mut body, protocol_version)?;
    Ok(pkt)
}

// Borrowed from mqudsi/tcpproxy
// https://github.com/mqudsi/tcpproxy/blob/e2d423b72898b497b129e8a58307934f9335974b/src/main.rs#L114C1-L159C6
// Quote
// Two instances of this function are spawned for each half of the connection: client-to-server,
// server-to-client. We can't use tokio::io::copy() instead (no matter how convenient it might
// be) because it doesn't give us a way to correlate the lifetimes of the two tcp read/write
// loops: even after the client disconnects, tokio would keep the upstream connection to the
// server alive until the connection's max client idle timeout is reached.
// Unquote
pub async fn copy_with_abort<R, W, L>(
    read: &mut R,
    write: &mut W,
    mut cancel: broadcast::Receiver<()>,
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
            }
            _ = cancel.recv() => {
                break;
            }
        }
        if bytes_read == 0 {
            break;
        }
        poll_size(bytes_read as u64);
        // While we ignore some read errors above, any error writing data we've already read to
        // the other side is always treated as exceptional.
        write.write_all(&buf[0..bytes_read]).await?;
        // Reduce poller wakes
        // write.flush().await?;
        // copied += bytes_read;
        // tokio::task::yield_now().await;
    }
    Ok(())
    // Ok(copied)
}

pub(crate) async fn passthrough_now<'a, 'b>(
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
