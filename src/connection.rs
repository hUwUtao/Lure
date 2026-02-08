use std::{
    fmt::Debug,
    io::{self, ErrorKind},
};

// use futures::FutureExt;
use net::{
    LoginDisconnectS2c, LoginStartC2s, PacketDecode, PacketDecoder, PacketEncode, PacketEncoder,
    PacketFrame, ProtoError, encode_raw_packet,
};
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter},
};
use serde_json::to_string as json_string;

use crate::{sock::LureConnection, telemetry::get_meter};

pub(crate) struct EncodedConnection<'a> {
    enc: PacketEncoder,
    dec: PacketDecoder,
    frame: PacketFrame,
    stream: &'a mut LureConnection,
    read_buf: Vec<u8>,
    metric: ConnectionMetric,
    intent: KeyValue,
    _reserved_lifetime: std::marker::PhantomData<&'a ()>,
}

pub struct LoginStartFrame<'a> {
    pub packet: LoginStartC2s<'a>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
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

impl PacketEncode for VersionedLoginStart<'_, '_> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> net::mc::Result<()> {
        self.packet
            .encode_body_with_version(out, self.protocol_version)
    }
}

impl<'a> EncodedConnection<'a> {
    pub fn new(stream: &'a mut LureConnection, intent: SocketIntent) -> Self {
        let metric = get_meter();
        Self {
            enc: PacketEncoder::new(),
            dec: PacketDecoder::new(),
            stream,
            frame: PacketFrame {
                id: 0,
                body: Vec::new(),
            },
            read_buf: vec![0u8; MAX_CHUNK_SIZE],
            metric: ConnectionMetric::new(&metric),
            intent: intent.as_attr(),
            _reserved_lifetime: std::marker::PhantomData,
        }
    }

    pub fn with_buffered(
        stream: &'a mut LureConnection,
        intent: SocketIntent,
        buffered: Vec<u8>,
    ) -> Self {
        let mut conn = Self::new(stream, intent);
        if !buffered.is_empty() {
            conn.dec.queue_slice(&buffered);
        }
        conn
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
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    fn drain_pending_inbound(&mut self) {
        let mut buf = [0u8; 1024];
        let mut drained = 0usize;
        loop {
            match self.stream.try_read(&mut buf) {
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

            let (read_len, buf) = self
                .stream
                .read_chunk(std::mem::take(&mut self.read_buf))
                .await?;
            self.read_buf = buf;
            if read_len == 0 {
                return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
            }
            self.dec.queue_slice(&self.read_buf[..read_len]);
        }
    }

    pub async fn recv_login_start<'b>(
        &'b mut self,
        protocol_version: i32,
    ) -> anyhow::Result<LoginStartFrame<'b>> {
        loop {
            if let Some(frame) = self.dec.try_next_packet()? {
                let size = frame.body.len();
                self.frame = frame;
                self.packet_record(size);
                let mut raw = Vec::new();
                encode_raw_packet(&mut raw, self.frame.id, &self.frame.body)?;
                let packet = decode_login_start_frame(&self.frame, protocol_version)?;
                return Ok(LoginStartFrame { packet, raw });
            }

            let (read_len, buf) = self
                .stream
                .read_chunk(std::mem::take(&mut self.read_buf))
                .await?;
            self.read_buf = buf;
            if read_len == 0 {
                return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
            }
            self.dec.queue_slice(&self.read_buf[..read_len]);
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
        let _ = self.stream.write_all(bytes).await?;
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
        let _ = self.stream.write_all(bytes).await?;
        self.flush().await?;
        Ok(())
    }

    pub async fn send_raw(&mut self, pkt: &[u8]) -> anyhow::Result<()> {
        let size = pkt.len();
        self.packet_record(size);
        let _ = self.stream.write_all(pkt.to_vec()).await?;
        self.flush().await?;
        Ok(())
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        self.stream.flush().await?;
        Ok(())
    }

    pub const fn as_inner_mut(&mut self) -> &mut LureConnection {
        self.stream
    }

    pub const fn as_inner(&self) -> &LureConnection {
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
