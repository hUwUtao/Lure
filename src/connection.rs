use std::{io, io::ErrorKind};

use bytes::BytesMut;
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    KeyValue,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};
use valence_protocol::{
    decode::PacketFrame, packets::login::LoginDisconnectS2c, Decode, Encode, Packet, PacketDecoder,
    PacketEncoder, Text,
};

use crate::{error::ReportableError, telemetry::get_meter, utils::Connection};

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
        loop {
            if let Some(frame) = self.dec.try_next_packet()? {
                let size = frame.body.len();
                self.frame = frame;
                self.packet_record(size);
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
        self.enc.append_packet::<P>(pkt)?;
        let bytes = self.enc.take();
        let size = bytes.len();
        self.packet_record(size);
        // timeout(Duration::from_millis(5000), self.write.write_all(&bytes)).await??;
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
