use futures::FutureExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};

use net::sock::tokio::Connection;

use crate::{
    error::ReportableError,
    inspect::drive_transport_metrics,
    logging::LureLogger,
    router::Session,
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
