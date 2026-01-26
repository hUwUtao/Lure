pub(crate) mod tokio;
pub(crate) mod uring;

use std::{io, net::SocketAddr, sync::OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendKind {
    Tokio,
    Uring,
}

#[derive(Debug, Clone)]
pub(crate) struct BackendSelection {
    pub(crate) kind: BackendKind,
    pub(crate) reason: String,
}

static BACKEND_SELECTION: OnceLock<BackendSelection> = OnceLock::new();

pub(crate) fn backend_kind() -> BackendKind {
    backend_selection().kind
}

pub(crate) fn backend_selection() -> &'static BackendSelection {
    BACKEND_SELECTION.get_or_init(|| match std::env::var("LURE_IO_URING").ok().as_deref() {
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

pub(crate) enum Listener {
    Tokio(tokio::Listener),
    Uring(uring::Listener),
}

impl Listener {
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Listener::bind(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Listener::bind(addr)?)),
        }
    }

    pub(crate) async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
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
}

pub(crate) enum Connection {
    Tokio(tokio::Connection),
    Uring(uring::Connection),
}

impl Connection {
    pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Connection::connect(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Connection::connect(addr).await?)),
        }
    }

    pub(crate) fn backend_kind(&self) -> BackendKind {
        match self {
            Self::Tokio(_) => BackendKind::Tokio,
            Self::Uring(_) => BackendKind::Uring,
        }
    }

    pub(crate) fn addr(&self) -> &SocketAddr {
        match self {
            Self::Tokio(conn) => conn.addr(),
            Self::Uring(conn) => conn.addr(),
        }
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.peer_addr(),
            Self::Uring(conn) => conn.peer_addr(),
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.local_addr(),
            Self::Uring(conn) => conn.local_addr(),
        }
    }

    pub(crate) async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        match self {
            Self::Tokio(conn) => conn.read_chunk(buf).await,
            Self::Uring(conn) => conn.read_chunk(buf).await,
        }
    }

    pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        match self {
            Self::Tokio(conn) => conn.write_all(buf).await,
            Self::Uring(conn) => conn.write_all(buf).await,
        }
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.flush().await,
            Self::Uring(conn) => conn.flush().await,
        }
    }

    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.set_nodelay(nodelay),
            Self::Uring(conn) => conn.set_nodelay(nodelay),
        }
    }

    pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tokio(conn) => conn.try_read(buf),
            Self::Uring(conn) => conn.try_read(buf),
        }
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.shutdown().await,
            Self::Uring(conn) => conn.shutdown().await,
        }
    }
}

pub(crate) async fn passthrough_now<'a, 'b>(
    client: &mut crate::connection::EncodedConnection<'a>,
    server: &mut crate::connection::EncodedConnection<'b>,
    session: &crate::router::Session,
) -> anyhow::Result<()> {
    let client = client.as_inner_mut();
    let server = server.as_inner_mut();
    match (client, server) {
        (Connection::Tokio(client), Connection::Tokio(server)) => {
            tokio::passthrough_now(client, server, session).await
        }
        (Connection::Uring(client), Connection::Uring(server)) => {
            uring::passthrough_now(client, server, session).await
        }
        _ => Err(anyhow::anyhow!(
            "mismatched connection backends for passthrough"
        )),
    }
}
