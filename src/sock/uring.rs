use std::{rc::Rc, sync::Arc};

use net::sock::uring::{Connection, StreamHandle, read_into_handle, spawn, write_all_handle};

use crate::{
    error::ReportableError, inspect::drive_transport_metrics, logging::LureLogger, router::Session,
    utils::UnsafeCounterU64,
};

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

        spawn(async move { forward_loop(from, to, cancel, |u| inspect.record_s2c(u)).await })
    };
    let b = {
        let cancel = Arc::clone(&cancel);
        let inspect = inspect.clone();
        let from = Rc::clone(&client_stream);
        let to = Rc::clone(&server_stream);
        spawn(async move { forward_loop(from, to, cancel, |u| inspect.record_c2s(u)).await })
    };
    let c = spawn(async move {
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
    from: StreamHandle,
    to: StreamHandle,
    cancel: Arc<UnsafeCounterU64>,
    poll_size: L,
) -> anyhow::Result<()>
where
    L: Fn(u64),
{
    const BUF_CAP: usize = 64 * 1024; /* Increased from 16KB to reduce syscalls on high throughput */
    let mut buf = Vec::with_capacity(BUF_CAP);
    loop {
        let (bytes_read, buf_out) = match read_into_handle(&from, buf).await {
            Ok((n, buf_out)) => (n, buf_out),
            Err(err) => {
                cancel.inc(1);
                return Err(ReportableError::from(err).into());
            }
        };
        buf = buf_out;
        if bytes_read == 0 {
            cancel.inc(1);
            return Ok(());
        }
        poll_size(bytes_read as u64);

        let write_buf = buf[..bytes_read].to_vec();
        if let Err(err) = write_all_handle(&to, write_buf).await {
            cancel.inc(1);
            return Err(ReportableError::from(err).into());
        }
    }
}
