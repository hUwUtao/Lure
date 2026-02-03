pub mod epoll;
pub mod tokio;
pub mod uring;

use std::{
    any::Any,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::OnceLock,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Tokio,
    Epoll,
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
    let override_env = std::env::var("LURE_IO_EPOLL")
        .ok()
        .or_else(|| std::env::var("NET_IO_EPOLL").ok());
    let uring_override = std::env::var("LURE_IO_URING")
        .ok()
        .or_else(|| std::env::var("NET_IO_URING").ok());
    BACKEND_SELECTION.get_or_init(|| match override_env.as_deref() {
        Some("0") => BackendSelection {
            kind: BackendKind::Tokio,
            reason: "LURE_IO_EPOLL=0 (forced tokio)".to_string(),
        },
        Some("1") => match epoll::probe() {
            Ok(()) => BackendSelection {
                kind: BackendKind::Epoll,
                reason: "LURE_IO_EPOLL=1 and epoll available".to_string(),
            },
            Err(err) => BackendSelection {
                kind: BackendKind::Tokio,
                reason: format!("LURE_IO_EPOLL=1 but {err}"),
            },
        },
        _ => match uring_override.as_deref() {
            Some("1") => match uring::probe() {
                Ok(()) => BackendSelection {
                    kind: BackendKind::Uring,
                    reason: "LURE_IO_URING=1 (explicit) and io_uring available".to_string(),
                },
                Err(err) => BackendSelection {
                    kind: BackendKind::Tokio,
                    reason: format!("LURE_IO_URING=1 but {err}"),
                },
            },
            Some("0") => BackendSelection {
                kind: BackendKind::Tokio,
                reason: "LURE_IO_URING=0 (forced tokio)".to_string(),
            },
            _ => BackendSelection {
                kind: BackendKind::Tokio,
                reason: "default tokio (io_uring probe disabled)".to_string(),
            },
        },
    })
}

pub enum Listener {
    Tokio(tokio::Listener),
    Epoll(epoll::Listener),
    Uring(uring::Listener),
}

impl Listener {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Listener::bind(addr).await?)),
            BackendKind::Epoll => Ok(Self::Epoll(epoll::Listener::bind(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Listener::bind(addr)?)),
        }
    }

    pub async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        match self {
            Self::Tokio(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Tokio(conn), addr))
            }
            Self::Epoll(listener) => {
                let (conn, addr) = listener.accept().await?;
                Ok((Connection::Epoll(conn), addr))
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
            Self::Epoll(listener) => listener.local_addr(),
            Self::Uring(listener) => listener.local_addr(),
        }
    }
}

pub enum Connection {
    Tokio(tokio::Connection),
    Epoll(epoll::Connection),
    Uring(uring::Connection),
}

impl Connection {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        match backend_kind() {
            BackendKind::Tokio => Ok(Self::Tokio(tokio::Connection::connect(addr).await?)),
            BackendKind::Epoll => Ok(Self::Epoll(epoll::Connection::connect(addr).await?)),
            BackendKind::Uring => Ok(Self::Uring(uring::Connection::connect(addr).await?)),
        }
    }

    pub fn backend_kind(&self) -> BackendKind {
        match self {
            Self::Tokio(_) => BackendKind::Tokio,
            Self::Epoll(_) => BackendKind::Epoll,
            Self::Uring(_) => BackendKind::Uring,
        }
    }

    pub fn addr(&self) -> &SocketAddr {
        match self {
            Self::Tokio(conn) => conn.addr(),
            Self::Epoll(conn) => conn.addr(),
            Self::Uring(conn) => conn.addr(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.peer_addr(),
            Self::Epoll(conn) => conn.peer_addr(),
            Self::Uring(conn) => conn.peer_addr(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tokio(conn) => conn.local_addr(),
            Self::Epoll(conn) => conn.local_addr(),
            Self::Uring(conn) => conn.local_addr(),
        }
    }

    pub async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        match self {
            Self::Tokio(conn) => conn.read_chunk(buf).await,
            Self::Epoll(conn) => conn.read_chunk(buf).await,
            Self::Uring(conn) => conn.read_chunk(buf).await,
        }
    }

    pub async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        match self {
            Self::Tokio(conn) => conn.write_all(buf).await,
            Self::Epoll(conn) => conn.write_all(buf).await,
            Self::Uring(conn) => conn.write_all(buf).await,
        }
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.flush().await,
            Self::Epoll(conn) => conn.flush().await,
            Self::Uring(conn) => conn.flush().await,
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.set_nodelay(nodelay),
            Self::Epoll(conn) => conn.set_nodelay(nodelay),
            Self::Uring(conn) => conn.set_nodelay(nodelay),
        }
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tokio(conn) => conn.try_read(buf),
            Self::Epoll(conn) => conn.try_read(buf),
            Self::Uring(conn) => conn.try_read(buf),
        }
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(conn) => conn.shutdown().await,
            Self::Epoll(conn) => conn.shutdown().await,
            Self::Uring(conn) => conn.shutdown().await,
        }
    }

    pub fn as_tokio_mut(&mut self) -> Option<&mut tokio::Connection> {
        match self {
            Self::Tokio(conn) => Some(conn),
            _ => None,
        }
    }

    pub fn as_epoll_mut(&mut self) -> Option<&mut epoll::Connection> {
        match self {
            Self::Epoll(conn) => Some(conn),
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
        (Connection::Epoll(a), Connection::Epoll(b)) => epoll::passthrough_basic(a, b).await,
        (Connection::Uring(a), Connection::Uring(b)) => uring::passthrough_basic(a, b).await,
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            "mismatched connection backends for passthrough",
        )),
    }
}

pub type BoxedConnection = Box<dyn SockConnection>;
pub type BoxedListener = Box<dyn SockListener>;

pub struct LureConnection(BoxedConnection);
pub struct LureListener(BoxedListener);

pub trait SockConnection {
    fn backend_kind(&self) -> BackendKind;
    fn addr(&self) -> &SocketAddr;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn read_chunk<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, Vec<u8>)>> + 'a>>;
    fn write_all<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + 'a>>;
    fn flush<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;
    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;
}

pub trait SockListener {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(BoxedConnection, SocketAddr)>> + 'a>>;
}

impl Connection {
    pub fn into_boxed(self) -> BoxedConnection {
        Box::new(self)
    }
}

impl Listener {
    pub fn into_boxed(self) -> BoxedListener {
        Box::new(self)
    }

    pub fn accept_boxed<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(BoxedConnection, SocketAddr)>> + 'a>> {
        Box::pin(async move {
            let (conn, addr) = self.accept().await?;
            Ok((conn.into_boxed(), addr))
        })
    }
}

impl SockConnection for Connection {
    fn backend_kind(&self) -> BackendKind {
        Connection::backend_kind(self)
    }

    fn addr(&self) -> &SocketAddr {
        Connection::addr(self)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Connection::peer_addr(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Connection::local_addr(self)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Connection::set_nodelay(self, nodelay)
    }

    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Connection::try_read(self, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn read_chunk<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, Vec<u8>)>> + 'a>> {
        Box::pin(async move { Connection::read_chunk(self, buf).await })
    }

    fn write_all<'a>(
        &'a mut self,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + 'a>> {
        Box::pin(async move { Connection::write_all(self, buf).await })
    }

    fn flush<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(async move { Connection::flush(self).await })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(async move { Connection::shutdown(self).await })
    }
}

impl SockListener for Listener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Listener::local_addr(self)
    }

    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(BoxedConnection, SocketAddr)>> + 'a>> {
        Box::pin(async move {
            let (conn, addr) = self.accept().await?;
            Ok((conn.into_boxed(), addr))
        })
    }
}

pub async fn connect_boxed(addr: SocketAddr) -> io::Result<BoxedConnection> {
    let conn = Connection::connect(addr).await?;
    Ok(conn.into_boxed())
}

pub async fn bind_boxed(addr: SocketAddr) -> io::Result<BoxedListener> {
    let listener = Listener::bind(addr).await?;
    Ok(listener.into_boxed())
}

impl LureListener {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self(bind_boxed(addr).await?))
    }

    pub async fn accept(&self) -> io::Result<(LureConnection, SocketAddr)> {
        let (conn, addr) = self.0.accept().await?;
        Ok((LureConnection(conn), addr))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl LureConnection {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self(connect_boxed(addr).await?))
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.0.backend_kind()
    }

    pub fn addr(&self) -> &SocketAddr {
        self.0.addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.0.set_nodelay(nodelay)
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.try_read(buf)
    }

    pub fn as_connection(&self) -> Option<&Connection> {
        self.0.as_any().downcast_ref::<Connection>()
    }

    pub fn as_connection_mut(&mut self) -> Option<&mut Connection> {
        self.0.as_any_mut().downcast_mut::<Connection>()
    }

    pub async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        self.0.read_chunk(buf).await
    }

    pub async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        self.0.write_all(buf).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.0.flush().await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

