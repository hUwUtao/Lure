use std::{os::fd::AsRawFd, sync::Arc};

use net::sock::epoll::{duplicate_fd, EpollBackend};

use crate::{error::ReportableError, inspect::drive_transport_metrics, router::Session};

extern crate num_cpus;

// Global thread pool for epoll-based passthrough
static EPOLL_BACKEND: std::sync::OnceLock<Arc<EpollBackend>> = std::sync::OnceLock::new();

fn get_epoll_backend() -> anyhow::Result<Arc<EpollBackend>> {
    Ok(EPOLL_BACKEND
        .get_or_init(|| {
            let workers = num_cpus::get();
            // Pre-allocate 1024 connection slots per worker
            match EpollBackend::new(workers, 1024, 8192) {
                Ok(backend) => Arc::new(backend),
                Err(e) => {
                    log::error!("Failed to initialize EpollBackend: {}", e);
                    panic!("Failed to initialize EpollBackend: {}", e);
                }
            }
        })
        .clone())
}

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

    // Get the global thread pool
    let backend = get_epoll_backend()?;

    // Dispatch to worker pool (non-blocking async)
    let rx = backend.spawn_pair(client_fd, server_fd)?;
    let done = rx
        .await
        .map_err(|e| ReportableError::from(anyhow::anyhow!("passthrough done channel closed: {}", e)))?;

    if done.result < 0 {
        let err = std::io::Error::from_raw_os_error(-done.result);
        return Err(ReportableError::from(anyhow::anyhow!("epoll passthrough failed: {}", err)).into());
    }

    session.inspect.record_c2s(done.stats.c2s_bytes);
    session.inspect.record_s2c(done.stats.s2c_bytes);

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = metrics_task.await;

    Ok(())
}
