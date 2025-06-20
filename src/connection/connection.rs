use bytes::BytesMut;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;
use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;
use valence_protocol::decode::PacketFrame;
use valence_protocol::packets::login::LoginDisconnectS2c;
use valence_protocol::{Decode, Encode, Packet, Text};
use valence_protocol::{PacketDecoder, PacketEncoder};
pub struct Connection {
    pub address: SocketAddr,
    pub enc: PacketEncoder,
    pub dec: PacketDecoder,
    pub read: OwnedReadHalf,
    pub write: OwnedWriteHalf,
    pub frame: PacketFrame,
}

const MAX_CHUNK_SIZE: usize = 1024;

impl<'o> Connection {
    pub fn new(address: SocketAddr, read: OwnedReadHalf, write: OwnedWriteHalf) -> Self {
        Self {
            address,
            enc: PacketEncoder::new(),
            dec: PacketDecoder::new(),
            read,
            write,
            frame: PacketFrame {
                id: 0,
                body: BytesMut::new(),
            },
        }
    }
    pub async fn create_conn(addr: SocketAddr) -> anyhow::Result<Connection> {
        let (r, w) = tokio::net::TcpStream::connect(addr).await?.into_split();
        let connection = Connection {
            address: addr,
            enc: PacketEncoder::new(),
            dec: PacketDecoder::new(),
            read: r,
            write: w,
            frame: PacketFrame {
                id: 0,
                body: BytesMut::new(),
            },
        };
        Ok(connection)
    }

    // pub fn enable_encryption(&mut self, key: &[u8; 16]) {
    //     self.enc.enable_encryption(key);
    //     self.dec.enable_encryption(key);
    // }

    pub async fn disconnect(&mut self, reason: Text) -> anyhow::Result<()> {
        let kick = LoginDisconnectS2c {
            reason: reason.into(),
        };
        self.send(&kick).await?;
        Ok(())
    }

    /// Valence packet recv
    /// https://github.com/valence-rs/valence/blob/main/crates/valence_network/src/packet_io.rs#L53
    pub async fn recv<'a, P>(&'a mut self) -> anyhow::Result<P>
    where
        P: Packet + Decode<'a>,
    {
        loop {
            if let Some(frame) = self.dec.try_next_packet()? {
                self.frame = frame;

                return self.frame.decode();
            }

            self.dec.reserve(MAX_CHUNK_SIZE);
            let mut buf = self.dec.take_capacity();

            if self.read.read_buf(&mut buf).await? == 0 {
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
        // timeout(Duration::from_millis(5000), self.write.write_all(&bytes)).await??;
        self.write.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn raw_pipe<'a>(&'a mut self) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_CHUNK_SIZE];

        loop {
            let bytes_read = self.read.read(&mut buf).await?;
            if bytes_read == 0 {
                break;
            }
            self.write.write_all(&buf[..bytes_read]).await?;
        }

        self.write.flush().await?;
        Ok(())
    }
}
