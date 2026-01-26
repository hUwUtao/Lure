use std::{
    io,
    net::SocketAddr,
    rc::Rc,
};

use tokio::sync::broadcast;
use tokio_uring::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    Submit,
};
use io_uring::IoUring;

use crate::{
    error::ReportableError,
    logging::LureLogger,
    router::Session,
    telemetry::get_meter,
};

pub(crate) fn probe() -> io::Result<()> {
    IoUring::new(1)
        .map(|_| ())
        .map_err(|err| io::Error::new(err.kind(), format!("io_uring syscall unavailable: {err}")))?;
    Runtime::new(&tokio_uring::builder())
        .map(|_| ())
        .map_err(|err| io::Error::new(err.kind(), format!("tokio-uring runtime init failed: {err}")))
}

pub(crate) struct Listener {
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
}

pub(crate) struct Connection {
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
        let len = buf.len();
        write_all_stream(self.stream.as_ref(), buf, len).await
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

pub(crate) async fn passthrough_now(
    client: &mut Connection,
    server: &mut Connection,
    session: &Session,
) -> anyhow::Result<()> {
    let cad = *client.addr();
    let rad = *server.addr();
    let client_stream = client.stream_handle();
    let server_stream = server.stream_handle();

    let (cancel, _) = broadcast::channel(1);
    let inspect = session.inspect.clone();

    let a = {
        let cancel = cancel.clone();
        let inspect = inspect.clone();
        let from = Rc::clone(&server_stream);
        let to = Rc::clone(&client_stream);
        tokio_uring::spawn(async move {
            forward_loop(from, to, cancel, |u| inspect.record_s2c(u)).await
        })
    };
    let b = {
        let cancel = cancel.clone();
        let inspect = inspect.clone();
        let from = Rc::clone(&client_stream);
        let to = Rc::clone(&server_stream);
        tokio_uring::spawn(async move {
            forward_loop(from, to, cancel, |u| inspect.record_c2s(u)).await
        })
    };
    let c = tokio_uring::spawn(async move {
        let abort = cancel.subscribe();
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        let volume_record = get_meter()
            .u64_counter("lure_proxy_transport_volume")
            .with_unit("bytes")
            .build();

        let packet_record = get_meter()
            .u64_counter("lure_proxy_transport_packet_count")
            .with_unit("packets")
            .build();

        let s2ct = opentelemetry::KeyValue::new("intent", "s2c");
        let c2st = opentelemetry::KeyValue::new("intent", "c2s");

        let mut last = inspect.traffic.snapshot();

        loop {
            if !abort.is_empty() {
                break;
            }

            let vr1 = volume_record.clone();
            let vr2 = volume_record.clone();
            let pr1 = packet_record.clone();
            let pr2 = packet_record.clone();

            let snap = inspect.traffic.snapshot();

            vr1.add(
                snap.c2s_bytes - last.c2s_bytes,
                core::slice::from_ref(&c2st),
            );
            vr2.add(
                snap.s2c_bytes - last.s2c_bytes,
                core::slice::from_ref(&s2ct),
            );
            pr1.add(
                snap.c2s_chunks - last.c2s_chunks,
                core::slice::from_ref(&c2st),
            );
            pr2.add(
                snap.s2c_chunks - last.s2c_chunks,
                core::slice::from_ref(&s2ct),
            );

            last = snap;

            interval.tick().await;
        }
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
    cancel: broadcast::Sender<()>,
    poll_size: L,
) -> anyhow::Result<()>
where
    L: Fn(u64),
{
    let mut buf = vec![0u8; 16 * 1024];
    let abort = cancel.subscribe();
    loop {
        let (bytes_read, buf_out) =
            match from.read(tokio_uring::buf::Buffer::from(buf)).await {
                Ok((n, buf_out)) => (n, buf_out),
                Err(err) => {
                    let _ = err.1;
                    let _ = cancel.send(());
                    return Err(ReportableError::from(err.0).into());
                }
            };
        buf = buf_out.try_into().unwrap_or_else(|_| vec![0u8; 16 * 1024]);

        if bytes_read == 0 {
            let _ = cancel.send(());
            break;
        }

        poll_size(bytes_read as u64);

        buf = match write_all_stream(to.as_ref(), buf, bytes_read).await {
            Ok(buf) => buf,
            Err(err) => {
                let _ = cancel.send(());
                return Err(ReportableError::from(err).into());
            }
        };
        buf.clear();
        if buf.capacity() < 16 * 1024 {
            buf.reserve_exact(16 * 1024 - buf.capacity());
        }

        if !abort.is_empty() {
            break;
        }
    }
    Ok(())
}

async fn write_all_stream(
    stream: &TcpStream,
    mut buf: Vec<u8>,
    mut len: usize,
) -> io::Result<Vec<u8>> {
    if len > buf.len() {
        len = buf.len();
    }
    buf.truncate(len);
    loop {
        let buffer = tokio_uring::buf::Buffer::from(buf);
        let (n, buffer) = match stream.write(buffer).submit().await {
            Ok((n, buffer)) => (n, buffer),
            Err(err) => return Err(err.0),
        };
        let mut vec = buffer.try_into().unwrap_or_else(|_| Vec::new());
        if n >= vec.len() {
            return Ok(vec);
        }
        vec.copy_within(n.., 0);
        let remaining = vec.len().saturating_sub(n);
        vec.truncate(remaining);
        buf = vec;
        if buf.is_empty() {
            return Ok(buf);
        }
    }
}
