use std::{io, net::SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Self { inner })
    }

    pub(crate) async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;
        Ok((Connection::new(stream, addr), addr))
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
}

impl TryFrom<TcpStream> for Connection {
    type Error = io::Error;

    fn try_from(stream: TcpStream) -> Result<Self, io::Error> {
        let addr = stream.peer_addr()?;
        Ok(Self { stream, addr })
    }
}

impl Connection {
    pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let addr = stream.peer_addr()?;
        Ok(Self { stream, addr })
    }

    pub(crate) fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        Self { stream, addr }
    }

    pub fn as_ref(&self) -> &TcpStream {
        &self.stream
    }

    pub fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    pub(crate) async fn read_chunk(&mut self, mut buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        let n = self.stream.read(buf.as_mut_slice()).await?;
        Ok((n, buf))
    }

    pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        self.stream.write_all(buf.as_slice()).await?;
        Ok(buf)
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
    }

    pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.try_read(buf)
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }
}
