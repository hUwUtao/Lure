use async_trait::async_trait;
use serde_json::json;
use tokio::net::TcpStream;

use crate::telemetry::{EventEnvelope, EventServiceInstance, event::EventHook};

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

pub fn placeholder_status_response(brand: &str, message: &str) -> String {
    json!({
        "version": {
            "name": brand,
            "protocol": -1
        },
        "description": {
            "text": message
        }
    })
    .to_string()
}

pub fn sanitize_hostname(input: &str) -> String {
    const FALLBACK: &str = "unknown-host";
    let sanitized: String = input
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(255)
        .collect();
    let sanitized = sanitized.trim().to_owned();
    if sanitized.is_empty() {
        FALLBACK.to_owned()
    } else {
        sanitized
    }
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

pub fn spawn_named<F>(
    name: &str,
    future: F,
) -> Result<tokio::task::JoinHandle<F::Output>, std::io::Error>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::task::Builder::new().name(name).spawn(future)
}
