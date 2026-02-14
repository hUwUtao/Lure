use std::{
    os::fd::RawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use net::sock::{
    ebpf::{EbpfProgress, EbpfStats, spawn_pair_observed},
    epoll::duplicate_fd,
};

use crate::{error::ReportableError, inspect::drive_transport_metrics, router::Session};

async fn pump_ebpf_progress(progress: Arc<EbpfProgress>, stop: Arc<AtomicBool>) -> EbpfStats {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        interval.tick().await;
        if stop.load(Ordering::Relaxed) {
            return progress.snapshot();
        }
    }
}

pub async fn passthrough_now(
    client_fd: RawFd,
    server_fd: RawFd,
    session: &Session,
) -> anyhow::Result<()> {
    let client_fd = duplicate_fd(client_fd)?;
    let server_fd = duplicate_fd(server_fd)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_metrics = Arc::clone(&stop);
    let inspect = session.inspect.clone();
    let metrics_task = tokio::spawn(async move {
        drive_transport_metrics(inspect, || stop_metrics.load(Ordering::Relaxed)).await;
    });

    let (rx, progress) = match spawn_pair_observed(client_fd, server_fd) {
        Ok(v) => v,
        Err(err) => {
            stop.store(true, Ordering::Relaxed);
            let _ = metrics_task.await;
            return Err(err.into());
        }
    };

    let stop_observe = Arc::clone(&stop);
    let observe_task =
        tokio::spawn(async move { pump_ebpf_progress(progress, stop_observe).await });

    let done = rx.await.map_err(|e| {
        ReportableError::from(anyhow::anyhow!("eBPF passthrough done channel closed: {e}"))
    });

    stop.store(true, Ordering::Relaxed);
    let (observe_res, _metrics_res) = tokio::join!(observe_task, metrics_task);

    let done = done?;
    let observed = observe_res.unwrap_or_default();
    log::debug!(
        "eBPF loop stats: polls={} disconnects={} (done polls={} disconnects={})",
        observed.loop_polls,
        observed.disconnect_events,
        done.stats.loop_polls,
        done.stats.disconnect_events
    );

    if done.result < 0 {
        let err = std::io::Error::from_raw_os_error(-done.result);
        return Err(anyhow::anyhow!("eBPF passthrough failed: {err}"));
    }

    Ok(())
}
