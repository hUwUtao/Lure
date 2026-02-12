use std::{os::fd::AsRawFd, sync::Arc};

use net::sock::epoll::{EpollBackend, EpollProgress, EpollStats, duplicate_fd};

use crate::{error::ReportableError, inspect::drive_transport_metrics, router::Session};

extern crate num_cpus;

// Global thread pool for epoll-based passthrough
static EPOLL_BACKEND: std::sync::OnceLock<Result<Arc<EpollBackend>, String>> =
    std::sync::OnceLock::new();

fn get_epoll_backend() -> anyhow::Result<Arc<EpollBackend>> {
    let result = EPOLL_BACKEND.get_or_init(|| {
        let workers = num_cpus::get();
        // Pre-allocate 1024 connection slots per worker
        match EpollBackend::new(workers, 1024, 8192) {
            Ok(backend) => Ok(Arc::new(backend)),
            Err(e) => {
                let err_msg = format!("Failed to initialize EpollBackend: {e}");
                log::error!("{err_msg}");
                Err(err_msg)
            }
        }
    });

    result
        .as_ref()
        .map(std::clone::Clone::clone)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

async fn pump_epoll_progress(
    inspect: Arc<crate::router::inspect::SessionInspectState>,
    progress: Arc<EpollProgress>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
    let mut last = progress.snapshot();

    loop {
        interval.tick().await;
        let snap = progress.snapshot();
        record_epoll_delta(&inspect, last, snap);
        last = snap;

        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            let final_snap = progress.snapshot();
            record_epoll_delta(&inspect, last, final_snap);
            break;
        }
    }
}

fn record_epoll_delta(
    inspect: &crate::router::inspect::SessionInspectState,
    last: EpollStats,
    snap: EpollStats,
) {
    let c2s_delta = snap.c2s_bytes.saturating_sub(last.c2s_bytes);
    let s2c_delta = snap.s2c_bytes.saturating_sub(last.s2c_bytes);
    if c2s_delta != 0 {
        inspect.record_c2s(c2s_delta);
    }
    if s2c_delta != 0 {
        inspect.record_s2c(s2c_delta);
    }
}

pub async fn passthrough_now(
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
        drive_transport_metrics(inspect, || {
            stop_metrics.load(std::sync::atomic::Ordering::Relaxed)
        })
        .await;
    });

    // Get the global thread pool
    let backend = get_epoll_backend()?;

    // Dispatch to worker pool (non-blocking async)
    let (rx, progress) = match backend.spawn_pair_observed(client_fd, server_fd) {
        Ok(v) => v,
        Err(e) => {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = metrics_task.await;
            return Err(e.into());
        }
    };
    let stop_observe = Arc::clone(&stop);
    let inspect_observe = session.inspect.clone();
    let observe_task = tokio::spawn(async move {
        pump_epoll_progress(inspect_observe, progress, stop_observe).await;
    });

    let done = rx.await.map_err(|e| {
        ReportableError::from(anyhow::anyhow!("passthrough done channel closed: {e}"))
    });

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (_observe_res, _metrics_res) = tokio::join!(observe_task, metrics_task);

    let done = done?;

    if done.result < 0 {
        let err = std::io::Error::from_raw_os_error(-done.result);
        return Err(anyhow::anyhow!("epoll passthrough failed: {err}"));
    }

    Ok(())
}
