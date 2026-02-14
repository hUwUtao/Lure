#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::os::fd::AsRawFd;

use futures::FutureExt;
use net::sock::tokio::Connection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
    time::{Duration, Instant, sleep},
};

use crate::{
    error::ReportableError, inspect::drive_transport_metrics, logging::LureLogger, router::Session,
};

async fn copy_with_abort<R, W, L>(
    read: &mut R,
    write: &mut W,
    mut cancel: broadcast::Receiver<()>,
    poll_size: L,
) -> anyhow::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
    L: Fn(u64),
{
    const BUF_CAP: usize = 16 * 1024;
    let mut buf = vec![0u8; BUF_CAP];
    loop {
        let bytes_read = tokio::select! {
            result = read.read(&mut buf) => {
                match result {
                    Ok(n) => n,
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => 0,
                        _ => return Err(ReportableError::from(e).into()),
                    },
                }
            }
            _ = cancel.recv() => {
                break;
            }
        };
        if bytes_read == 0 {
            break;
        }
        poll_size(bytes_read as u64);
        write.write_all(&buf[0..bytes_read]).await?;
    }
    Ok(())
}

async fn drain_pending(
    from: &mut Connection,
    to: &mut Connection,
    inspect: &crate::router::inspect::SessionInspectState,
    s2c: bool,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.as_ref().try_read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                to.as_mut().write_all(&buf[..n]).await?;
                if s2c {
                    inspect.record_s2c(n as u64);
                } else {
                    inspect.record_c2s(n as u64);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

async fn pre_offload_pump(
    client: &mut Connection,
    server: &mut Connection,
    inspect: &crate::router::inspect::SessionInspectState,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(40);
    loop {
        let mut moved = false;
        {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match server.as_ref().try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        client.as_mut().write_all(&buf[..n]).await?;
                        inspect.record_s2c(n as u64);
                        moved = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err.into()),
                }
            }
        }
        {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match client.as_ref().try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        server.as_mut().write_all(&buf[..n]).await?;
                        inspect.record_c2s(n as u64);
                        moved = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err.into()),
                }
            }
        }

        if Instant::now() >= deadline {
            break;
        }
        if !moved {
            sleep(Duration::from_millis(1)).await;
        }
    }
    Ok(())
}

pub async fn passthrough_now(
    client: &mut Connection,
    server: &mut Connection,
    session: &Session,
) -> anyhow::Result<()> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        if net::sock::ebpf::ebpf_enabled() {
            pre_offload_pump(client, server, &session.inspect).await?;
            drain_pending(server, client, &session.inspect, true).await?;
            drain_pending(client, server, &session.inspect, false).await?;
            return crate::sock::ebpf::passthrough_now(
                client.as_ref().as_raw_fd(),
                server.as_ref().as_raw_fd(),
                session,
            )
            .await;
        }
    }

    let cad = *client.addr();
    let rad = *server.addr();
    let (mut client_read, mut client_write) = client.as_mut().split();
    let (mut remote_read, mut remote_write) = server.as_mut().split();

    let (cancel, _) = broadcast::channel(1);
    let inspect = session.inspect.clone();

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
        {
            let abort = cancel.subscribe();

            async move {
                drive_transport_metrics(inspect, || !abort.is_empty()).await;
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
