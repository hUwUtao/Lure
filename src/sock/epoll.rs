use std::{os::fd::AsRawFd, sync::Arc, time::Duration};

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

    let stats = tokio::task::spawn_blocking(move || passthrough(client_fd, server_fd))
        .await
        .map_err(|err| ReportableError::from(anyhow::anyhow!(err.to_string())))??;

    session.inspect.record_c2s(stats.c2s_bytes);
    session.inspect.record_s2c(stats.s2c_bytes);

    tokio::time::sleep(Duration::from_millis(110)).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = metrics_task.await;

    Ok(())
}
