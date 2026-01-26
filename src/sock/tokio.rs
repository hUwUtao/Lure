use std::{
    io,
    net::SocketAddr,
    time::Duration,
};

use futures::FutureExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};

use crate::{
    error::ReportableError,
    logging::LureLogger,
    router::Session,
    telemetry::get_meter,
};

pub(crate) struct Listener {
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
}

pub(crate) struct Connection {
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

    pub(crate) fn as_ref(&self) -> &TcpStream {
        &self.stream
    }

    pub(crate) fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
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

// Borrowed from mqudsi/tcpproxy
// https://github.com/mqudsi/tcpproxy/blob/e2d423b72898b497b129e8a58307934f9335974b/src/main.rs#L114C1-L159C6
// Quote
// Two instances of this function are spawned for each half of the connection: client-to-server,
// server-to-client. We can't use tokio::io::copy() instead (no matter how convenient it might
// be) because it doesn't give us a way to correlate the lifetimes of the two tcp read/write
// loops: even after the client disconnects, tokio would keep the upstream connection to the
// server alive until the connection's max client idle timeout is reached.
// Unquote
pub(crate) async fn copy_with_abort<R, W, L>(
    read: &mut R,
    write: &mut W,
    mut cancel: broadcast::Receiver<()>,
    poll_size: L,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    L: Fn(u64),
{
    let mut buf = [0u8; 1024];
    loop {
        let bytes_read;
        tokio::select! {
            res = read.read(&mut buf) => {
                bytes_read = match res {
                    Ok(n) => n,
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => 0,
                        _ => return Err(ReportableError::from(e).into()),
                    },
                };
            }
            _ = cancel.recv() => {
                break;
            }
        }
        if bytes_read == 0 {
            break;
        }
        poll_size(bytes_read as u64);
        write.write_all(&buf[0..bytes_read]).await?;
    }
    Ok(())
}

pub(crate) async fn passthrough_now(
    client: &mut Connection,
    server: &mut Connection,
    session: &Session,
) -> anyhow::Result<()> {
    let cad = *client.addr();
    let rad = *server.addr();
    let (mut client_read, mut client_write) = client.as_mut().split();
    let (mut remote_read, mut remote_write) = server.as_mut().split();

    let (cancel, _) = broadcast::channel(1);
    let inspect = session.inspect.clone();

    // Allows lint & fmt
    let (la, lb, lc) = (
        {
            let inspect = inspect.clone();
            copy_with_abort(
                &mut remote_read,
                &mut client_write,
                cancel.subscribe(),
                move |u| {
                    inspect.record_s2c(u);
                },
            )
            .then(|r| {
                let _ = cancel.send(());
                async { r }
            })
        },
        {
            let inspect = inspect.clone();
            copy_with_abort(
                &mut client_read,
                &mut remote_write,
                cancel.subscribe(),
                move |u| {
                    inspect.record_c2s(u);
                },
            )
            .then(|r| {
                let _ = cancel.send(());
                async { r }
            })
        },
        // Meter report thread
        {
            let abort = cancel.subscribe();

            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
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
            }
        },
    );
    let (ra, rb, _rc) = tokio::join!(la, lb, lc);

    if let Err(era) = ra {
        LureLogger::connection_error(&cad, Some(&rad), &era);
    }
    if let Err(erb) = rb {
        LureLogger::connection_error(&cad, Some(&rad), &erb);
    }

    Ok(())
}
