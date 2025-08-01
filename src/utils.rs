use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::telemetry::{event::EventHook, EventEnvelope, EventServiceInstance};

#[cfg(feature = "mimalloc")]
mod mimalloc {
    use mimalloc::MiMalloc;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
}

pub struct OwnedStatic<T: 'static>(&'static T);

impl<T> From<&'static T> for OwnedStatic<T> {
    fn from(value: &'static T) -> Self {
        OwnedStatic(value)
    }
}

#[async_trait]
impl<H: EventHook<EventEnvelope, EventEnvelope> + Send + Sync>
    EventHook<EventEnvelope, EventEnvelope> for OwnedStatic<H>
{
    async fn on_handshake(&self) -> Option<EventEnvelope> {
        self.0.on_handshake().await
    }

    async fn on_event(
        &self,
        inst: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        self.0.on_event(inst, event).await?;
        Ok(())
    }
}

pub fn leak<T>(inner: T) -> &'static T {
    Box::leak(Box::new(inner))
}

pub struct Connection {
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
}

impl TryFrom<TcpStream> for Connection {
    type Error = anyhow::Error;

    fn try_from(stream: TcpStream) -> anyhow::Result<Self> {
        let addr = stream.peer_addr()?;
        Ok(Self { stream, addr })
    }
}

impl Connection {
    pub fn new(stream: tokio::net::TcpStream, addr: std::net::SocketAddr) -> Self {
        Self { stream, addr }
    }

    pub fn as_ref(&self) -> &tokio::net::TcpStream {
        &self.stream
    }

    pub fn as_mut(&mut self) -> &mut tokio::net::TcpStream {
        &mut self.stream
    }

    pub fn addr(&self) -> &std::net::SocketAddr {
        &self.addr
    }
}
