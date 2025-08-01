use std::{io, io::ErrorKind};

use bytes::BytesMut;
use opentelemetry::{
    global,
    metrics::{Counter, Meter},
    KeyValue,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use valence_protocol::{
    decode::PacketFrame, packets::login::LoginDisconnectS2c, Decode, Encode, Packet, PacketDecoder,
    PacketEncoder, Text,
};

use crate::{telemetry::get_meter, utils::Connection};

pub struct EncodedConnection<'a> {
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
    PassthroughClientBound,
    PassthroughServerBound,
    Generic,
}

impl SocketIntent {
    fn as_attr(&self) -> KeyValue {
        // recv+pipe/send
        let a = match self {
            Self::GreetToProxy => "frontbound",
            Self::GreetToBackend => "backbound",
            Self::PassthroughClientBound => "s2c",
            Self::PassthroughServerBound => "c2s",
            Self::Generic => "generic",
        };
        KeyValue::new("intent", a)
    }
}

struct ConnectionMetric {
    packet_count: Counter<u64>,
}

impl ConnectionMetric {
    fn new(metric: &Meter) -> Self {
        Self {
            packet_count: metric.u64_counter("lure_proxy_packet_count").build(),
        }
    }
}

const MAX_CHUNK_SIZE: usize = 1024;

impl<'a> EncodedConnection<'a> {
    pub fn new(stream: &'a mut Connection, intent: SocketIntent) -> Self {
        let metric = get_meter();
        Self {
            enc: PacketEncoder::new(),
            dec: PacketDecoder::new(),
            stream,
            frame: PacketFrame {
                id: 0,
                body: BytesMut::new(),
            },
            metric: ConnectionMetric::new(&metric),
            intent: intent.as_attr(),
            _reserved_lifetime: std::marker::PhantomData,
        }
    }

    fn packet_record(&self) {
        self.metric.packet_count.add(1, &[self.intent.clone()]);
    }

    pub async fn connect(stream: &'a mut Connection) -> anyhow::Result<Self> {
        let metric = global::meter("alure-conn");
        let connection = EncodedConnection {
            enc: PacketEncoder::new(),
            dec: PacketDecoder::new(),
            stream,
            frame: PacketFrame {
                id: 0,
                body: BytesMut::new(),
            },
            metric: ConnectionMetric::new(&metric),
            intent: SocketIntent::Generic.as_attr(),
            _reserved_lifetime: std::marker::PhantomData,
        };
        Ok(connection)
    }

    // pub fn enable_encryption(&mut self, key: &[u8; 16]) {
    //     self.enc.enable_encryption(key);
    //     self.dec.enable_encryption(key);
    // }

    pub async fn disconnect_player(&mut self, reason: Text) -> anyhow::Result<()> {
        let kick = LoginDisconnectS2c {
            reason: reason.into(),
        };
        self.send(&kick).await?;
        Ok(())
    }

    /// Valence packet recv
    /// https://github.com/valence-rs/valence/blob/main/crates/valence_network/src/packet_io.rs#L53
    pub async fn recv<'b, P>(&'b mut self) -> anyhow::Result<P>
    where
        P: Packet + Decode<'b>,
    {
        self.packet_record();
        loop {
            if let Some(frame) = self.dec.try_next_packet()? {
                self.frame = frame;
                return self.frame.decode();
            }

            self.dec.reserve(MAX_CHUNK_SIZE);
            let mut buf = self.dec.take_capacity();

            if self.stream.as_mut().read_buf(&mut buf).await? == 0 {
                return Err(io::Error::from(ErrorKind::UnexpectedEof).into());
            }

            self.dec.queue_bytes(buf);
        }
    }

    pub async fn send<P>(&mut self, pkt: &P) -> anyhow::Result<()>
    where
        P: Encode + Packet,
    {
        self.packet_record();
        self.enc.append_packet::<P>(pkt)?;
        let bytes = self.enc.take();
        // timeout(Duration::from_millis(5000), self.write.write_all(&bytes)).await??;
        self.stream.as_mut().write_all(&bytes).await?;
        self.flush().await?;
        Ok(())
    }

    pub async fn send_raw(&mut self, pkt: &[u8]) -> anyhow::Result<()> {
        self.packet_record();
        self.stream.as_mut().write_all(pkt).await?;
        self.flush().await?;
        Ok(())
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        self.stream.as_mut().flush().await?;
        Ok(())
    }

    pub fn as_inner_mut(&mut self) -> &mut Connection {
        &mut self.stream
    }

    pub fn as_inner(&self) -> &Connection {
        &self.stream
    }
}
