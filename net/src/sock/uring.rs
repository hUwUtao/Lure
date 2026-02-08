use std::{io, net::SocketAddr, rc::Rc};

use io_uring::IoUring;
use tokio_uring::{
    Submit,
    buf::Buffer,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

pub type StreamHandle = Rc<TcpStream>;

pub(crate) fn probe() -> io::Result<()> {
    IoUring::new(1).map(|_| ()).map_err(|err| {
        io::Error::new(err.kind(), format!("io_uring syscall unavailable: {err}"))
    })?;
    Runtime::new(&tokio_uring::builder())
        .map(|_| ())
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("tokio-uring runtime init failed: {err}"),
            )
        })
}

pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + 'static,
    F::Output: 'static,
{
    tokio_uring::spawn(future)
}

pub fn start<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    tokio_uring::start(future)
}

pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    pub(crate) fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = TcpListener::bind(addr)?;
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
    stream: Rc<TcpStream>,
    addr: SocketAddr,
}

impl Connection {
    pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let addr = stream.peer_addr()?;
        Ok(Self::new(stream, addr))
    }

    pub(crate) fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        Self {
            stream: Rc::new(stream),
            addr,
        }
    }

    #[must_use]
    pub const fn addr(&self) -> &SocketAddr {
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

    #[must_use]
    pub fn stream_handle(&self) -> StreamHandle {
        Rc::clone(&self.stream)
    }

    pub(crate) async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        match self.stream.read(Buffer::from(buf)).await {
            Ok((n, buf)) => match buf.try_into::<Vec<u8>>() {
                Ok(out) => Ok((n, out)),
                Err(_) => Err(io::Error::other("failed to convert io_uring buffer")),
            },
            Err(err) => {
                let _ = err.1;
                Err(err.0)
            }
        }
    }

    pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        write_all_stream_handle(&self.stream, buf).await
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn try_read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "try_read is not supported for io_uring backend",
        ))
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
}

pub async fn read_into_handle(stream: &StreamHandle, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
    match stream.read(Buffer::from(buf)).await {
        Ok((n, buf)) => match buf.try_into::<Vec<u8>>() {
            Ok(out) => Ok((n, out)),
            Err(_) => Err(io::Error::other("failed to convert io_uring buffer")),
        },
        Err(err) => {
            let _ = err.1;
            Err(err.0)
        }
    }
}

pub async fn write_all_handle(stream: &StreamHandle, buf: Vec<u8>) -> io::Result<Vec<u8>> {
    write_all_stream_handle(stream, buf).await
}

pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
    let a_stream = a.stream_handle();
    let b_stream = b.stream_handle();
    let left = spawn(async move { relay(a_stream, b_stream).await });
    let b_stream = b.stream_handle();
    let a_stream = a.stream_handle();
    let right = spawn(async move { relay(b_stream, a_stream).await });
    let left_res = left.await?;
    left_res?;
    let right_res = right.await?;
    right_res?;
    Ok(())
}

async fn relay(from: StreamHandle, to: StreamHandle) -> io::Result<()> {
    const BUF_CAP: usize = 64 * 1024; /* Increased from 16KB to reduce syscalls on high throughput */
    let mut buf = vec![0u8; BUF_CAP];
    loop {
        let (n, out) = read_into_handle(&from, buf).await?;
        buf = out;
        if n == 0 {
            return Ok(());
        }
        /* Optimize: pass only needed data to write, reuse buffer on next iteration */
        buf.truncate(n);
        buf = write_all_handle(&to, buf).await?;
        /* Resize buffer back to capacity for next read operation */
        buf.resize(BUF_CAP, 0);
    }
}

async fn write_all_stream_handle(stream: &TcpStream, buf: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut pending = buf;
    loop {
        let buffer = Buffer::from(pending);
        let (written, buffer): (usize, Buffer) = match stream.write(buffer).submit().await {
            Ok((n, buffer)) => (n, buffer),
            Err(err) => {
                let _ = err.1;
                return Err(err.0);
            }
        };
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        let out = match buffer.try_into::<Vec<u8>>() {
            Ok(out) => out,
            Err(_) => {
                return Err(io::Error::other("failed to convert io_uring buffer"));
            }
        };
        if written >= out.len() {
            return Ok(out);
        }
        pending = out[written..].to_vec();
    }
}
