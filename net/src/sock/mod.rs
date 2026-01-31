pub mod tokio;
pub mod uring;

use std::{io, net::SocketAddr, sync::OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Tokio,
    Uring,
}

#[derive(Debug, Clone)]
pub struct BackendSelection {
    pub kind: BackendKind,
    pub reason: String,
}

static BACKEND_SELECTION: OnceLock<BackendSelection> = OnceLock::new();

pub fn backend_kind() -> BackendKind {
    backend_selection().kind
}

pub fn backend_selection() -> &'static BackendSelection {
    let override_env = std::env::var("LURE_IO_URING")
        .ok()
        .or_else(|| std::env::var("NET_IO_URING").ok());
    BACKEND_SELECTION.get_or_init(|| match override_env.as_deref() {
        Some("0") => BackendSelection {
            kind: BackendKind::Tokio,
            reason: "LURE_IO_URING=0 (forced tokio)".to_string(),
        },
        Some("1") => match uring::probe() {
            Ok(()) => BackendSelection {
                kind: BackendKind::Uring,
                reason: "LURE_IO_URING=1 and io_uring syscall available".to_string(),
            },
            Err(err) => BackendSelection {
                kind: BackendKind::Tokio,
                reason: format!("LURE_IO_URING=1 but {err}"),
            },
        },
        _ => match uring::probe() {
            Ok(()) => BackendSelection {
                kind: BackendKind::Uring,
                reason: "io_uring syscall available".to_string(),
            },
            Err(err) => BackendSelection {
                kind: BackendKind::Tokio,
                reason: format!("io_uring unavailable: {err}"),
            },
        },
    })
}

pub enum Listener {
    Tokio(tokio::Listener),
    Uring(uring::Listener),
}

impl Listener {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Listener::bind(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Listener::bind(addr)?)),
        }
    }

    pub async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        match self {
            Self::Tokio(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Tokio(conn), addr))
            }
            Self::Uring(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Uring(conn), addr))
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(listener) => listener.local_addr(),
            Self::Uring(listener) => listener.local_addr(),
        }
    }
}

pub enum Connection {
    Tokio(tokio::Connection),
    Uring(uring::Connection),
}

impl Connection {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Connection::connect(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Connection::connect(addr).await?)),
        }
    }

    pub fn backend_kind(&self) -> BackendKind {
        match self {
            Self::Tokio(_) => BackendKind::Tokio,
            Self::Uring(_) => BackendKind::Uring,
        }
    }

    pub fn addr(&self) -> &SocketAddr {
        match self {
            Self::Tokio(conn) => conn.addr(),
            Self::Uring(conn) => conn.addr(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.peer_addr(),
            Self::Uring(conn) => conn.peer_addr(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.local_addr(),
            Self::Uring(conn) => conn.local_addr(),
        }
    }

    pub async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        match self {
            Self::Tokio(conn) => conn.read_chunk(buf).await,
            Self::Uring(conn) => conn.read_chunk(buf).await,
        }
    }

    pub async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        match self {
            Self::Tokio(conn) => conn.write_all(buf).await,
            Self::Uring(conn) => conn.write_all(buf).await,
        }
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.flush().await,
            Self::Uring(conn) => conn.flush().await,
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.set_nodelay(nodelay),
            Self::Uring(conn) => conn.set_nodelay(nodelay),
        }
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tokio(conn) => conn.try_read(buf),
            Self::Uring(conn) => conn.try_read(buf),
        }
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.shutdown().await,
            Self::Uring(conn) => conn.shutdown().await,
        }
    }

    pub fn as_tokio_mut(&mut self) -> Option<&mut tokio::Connection> {
        match self {
            Self::Tokio(conn) => Some(conn),
            _ => None,
        }
    }

    pub fn as_uring_mut(&mut self) -> Option<&mut uring::Connection> {
        match self {
            Self::Uring(conn) => Some(conn),
            _ => None,
        }
    }
}

pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
    match (a, b) {
        (Connection::Tokio(a), Connection::Tokio(b)) => tokio::passthrough_basic(a, b).await,
        (Connection::Uring(a), Connection::Uring(b)) => uring::passthrough_basic(a, b).await,
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            "mismatched connection backends for passthrough",
        )),
    }
}
