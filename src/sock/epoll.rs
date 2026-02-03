use std::{os::fd::AsRawFd, sync::Arc, thread};

use net::sock::epoll::{duplicate_fd, passthrough};

use crate::{error::ReportableError, inspect::drive_transport_metrics, router::Session};

pub(crate) async fn passthrough_now(
    client: &mut net::sock::epoll::Connection,
    server: &mut net::sock::epoll::Connection,
    session: &Session,
) -> anyhow::Result<()> {
    let client_fd = duplicate_fd(client.as_ref().as_raw_fd())?;
    let server_fd = duplicate_fd(server.as_ref().as_raw_fd())?;

    let inspect = session.inspect.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_metrics = Arc::clone(&stop);

    let metrics_task = tokio::spawn(async move {
        drive_transport_metrics(inspect, || stop_metrics.load(std::sync::atomic::Ordering::Relaxed))
            .await;
    });

    // Spawn a plain OS thread to do the synchronous passthrough work
    let passthrough_thread = thread::spawn(move || passthrough(client_fd, server_fd));

    // Wait for the thread to finish (blocks until done)
    let stats = passthrough_thread
        .join()
        .map_err(|_| ReportableError::from(anyhow::anyhow!("passthrough thread panicked")))?
        .map_err(|e| ReportableError::from(anyhow::anyhow!(e.to_string())))?;

    session.inspect.record_c2s(stats.c2s_bytes);
    session.inspect.record_s2c(stats.s2c_bytes);

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = metrics_task.await;

    Ok(())
}
