use std::{io, net::SocketAddr, rc::Rc, sync::Arc};

use io_uring::IoUring;
use tokio_uring::{
    Submit,
    buf::BufferImpl,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

use crate::{
    error::ReportableError,
    inspect::drive_transport_metrics,
    logging::LureLogger,
    router::Session,
    utils::UnsafeCounterU64,
};

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

    pub(crate) fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    pub(crate) async fn read_chunk(&mut self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        let buffer = tokio_uring::buf::Buffer::from(buf);
        match self.stream.read(buffer).await {
            Ok((n, buffer)) => {
                let buf = buffer
                    .try_into::<Vec<u8>>()
                    .expect("tokio-uring buffer conversion failed");
                Ok((n, buf))
            }
            Err(err) => Err(err.0),
        }
    }

    pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        write_all_stream(self.stream.as_ref(), buf).await
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn try_read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    fn stream_handle(&self) -> Rc<TcpStream> {
        Rc::clone(&self.stream)
    }
}

struct WriteBuf {
    buf: Vec<u8>,
    offset: usize,
}

impl WriteBuf {
    fn new(buf: Vec<u8>) -> Self {
        Self { buf, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    fn advance(&mut self, n: usize) {
        self.offset = self.offset.saturating_add(n);
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

// Offsets the iovec pointer without copying bytes in userland.
unsafe impl BufferImpl for WriteBuf {
    type UserData = (Vec<u8>, usize);

    fn into_raw_parts(self) -> (Vec<*mut u8>, Vec<usize>, Vec<usize>, Self::UserData) {
        let mut buf = self.buf;
        let offset = self.offset;
        let len = buf.len().saturating_sub(offset);
        let ptr = unsafe { buf.as_mut_ptr().add(offset) };
        (vec![ptr], vec![len], vec![len], (buf, offset))
    }

    unsafe fn from_raw_parts(
        _ptr: Vec<*mut u8>,
        _len: Vec<usize>,
        _cap: Vec<usize>,
        user_data: Self::UserData,
    ) -> Self {
        let (buf, offset) = user_data;
        Self { buf, offset }
    }
}

pub(crate) async fn passthrough_now(
    client: &mut Connection,
    server: &mut Connection,
    session: &Session,
) -> anyhow::Result<()> {
    let cad = *client.addr();
    let rad = *server.addr();
    let client_stream = client.stream_handle();
    let server_stream = server.stream_handle();

    let cancel = Arc::new(UnsafeCounterU64::default());
    let inspect = session.inspect.clone();

    let a = {
        let cancel = Arc::clone(&cancel);
        let from = Rc::clone(&server_stream);
        let to = Rc::clone(&client_stream);
        let inspect = inspect.clone();

        tokio_uring::spawn(async move {
            forward_loop(from, to, cancel, |u| inspect.record_s2c(u)).await
        })
    };
    let b = {
        let cancel = Arc::clone(&cancel);
        let inspect = inspect.clone();
        let from = Rc::clone(&client_stream);
        let to = Rc::clone(&server_stream);
        tokio_uring::spawn(async move {
            forward_loop(from, to, cancel, |u| inspect.record_c2s(u)).await
        })
    };
    let c = tokio_uring::spawn(async move {
        let cancel = Arc::clone(&cancel);
        drive_transport_metrics(inspect, || cancel.load() != 0).await;
        Ok::<(), anyhow::Error>(())
    });

    let ra = a.await?;
    let rb = b.await?;
    let _rc = c.await?;

    if let Err(era) = ra {
        LureLogger::connection_error(&cad, Some(&rad), &era);
    }
    if let Err(erb) = rb {
        LureLogger::connection_error(&cad, Some(&rad), &erb);
    }

    Ok(())
}

async fn forward_loop<L>(
    from: Rc<TcpStream>,
    to: Rc<TcpStream>,
    cancel: Arc<UnsafeCounterU64>,
    poll_size: L,
) -> anyhow::Result<()>
where
    L: Fn(u64),
{
    const BUF_CAP: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(BUF_CAP);
    loop {
        let (bytes_read, buf_out) = match from.read(tokio_uring::buf::Buffer::from(buf)).await {
            Ok((n, buf_out)) => (n, buf_out),
            Err(err) => {
                let _ = err.1;
                cancel.inc(1);
                return Err(ReportableError::from(err.0).into());
            }
        };
        buf = buf_out
            .try_into()
            .expect("tokio-uring buffer conversion failed");

        if bytes_read == 0 {
            cancel.inc(1);
            break;
        }

        poll_size(bytes_read as u64);

        let mut write_buf = WriteBuf::new(buf);
        while write_buf.remaining() > 0 {
            let buffer = tokio_uring::buf::Buffer::from(write_buf);
            let (written, buffer) = match to.write(buffer).submit().await {
                Ok((n, buffer)) => (n, buffer),
                Err(err) => {
                    cancel.inc(1);
                    return Err(ReportableError::from(err.0).into());
                }
            };
            write_buf = buffer
                .try_into()
                .expect("tokio-uring buffer conversion failed");

            if written == 0 {
                cancel.inc(1);
                return Ok(());
            }

            write_buf.advance(written);
        }

        buf = write_buf.into_vec();
        buf.clear();
    }
    Ok(())
}

async fn write_all_stream(stream: &TcpStream, buf: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut write_buf = WriteBuf::new(buf);
    while write_buf.remaining() > 0 {
        let buffer = tokio_uring::buf::Buffer::from(write_buf);
        let (written, buffer) = match stream.write(buffer).submit().await {
            Ok((n, buffer)) => (n, buffer),
            Err(err) => return Err(err.0),
        };
        write_buf = buffer
            .try_into()
            .expect("tokio-uring buffer conversion failed");

        if written == 0 {
            return Ok(write_buf.into_vec());
        }

        write_buf.advance(written);
    }
    Ok(write_buf.into_vec())
}
