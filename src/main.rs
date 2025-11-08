pub(crate) mod config;
pub(crate) mod connection;
pub(crate) mod error;
pub(crate) mod logging;
pub(crate) mod lure;
pub(crate) mod metrics;
pub(crate) mod packet;
pub(crate) mod router;
pub(crate) mod telemetry;
pub(crate) mod threat;
pub(crate) mod utils;

use std::{env, error::Error, io::ErrorKind};

use config::LureConfig;
use libc::SIGCONT;
use lure::Lure;
use tokio::sync::broadcast;

use crate::{
    config::LureConfigLoadError,
    telemetry::{oltp::init_meter, process::ProcessMetricsService},
    utils::{leak, spawn_named},
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = dotenvy::dotenv();
    console_subscriber::init();
    #[cfg(debug_assertions)]
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    #[cfg(not(debug_assertions))]
    env_logger::init();

    let providers = if dotenvy::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        Some((init_meter(), 0u8))
    } else {
        None
    };

    let current_dir = env::current_dir()?;
    let config_file = current_dir.join("settings.toml");

    let config = match LureConfig::load(&config_file) {
        Ok(config) => config,
        Err(LureConfigLoadError::Io(io)) => {
            if io.kind() == ErrorKind::NotFound {
                let config = LureConfig::default();
                config.save(&config_file)?;
                config
            } else {
                return Err(io.into());
            }
        }
        Err(LureConfigLoadError::Parse(parse_error)) => return Err(parse_error.into()),
    };

    let pmt = leak(ProcessMetricsService::new());
    pmt.start();

    let lure = leak(Lure::new(config));
    lure.sync_routes_from_config().await?;

    let reload_path = config_file.clone();
    let reload_lure = lure;
    spawn_named("Reload handler", async move {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigcont = match signal(SignalKind::from_raw(SIGCONT)) {
            Ok(sig) => sig,
            Err(err) => {
                log::error!("Failed to register SIGCONT handler: {err}");
                return;
            }
        };

        while sigcont.recv().await.is_some() {
            match LureConfig::load(&reload_path) {
                Ok(cfg) => {
                    if let Err(err) = reload_lure.reload_config(cfg).await {
                        log::error!("Failed to apply reloaded config: {err:?}");
                    }
                }
                Err(LureConfigLoadError::Io(io)) if io.kind() == ErrorKind::NotFound => {
                    if let Err(err) = reload_lure.reload_config(LureConfig::default()).await {
                        log::error!("Failed to apply default config during reload: {err:?}");
                    }
                }
                Err(err) => {
                    log::error!("Failed to load config during reload: {err}");
                }
            }
        }
    })?;

    spawn_named("Main thread", async move {
        if let Err(e) = lure.start().await {
            log::error!("{e}");
        }
        if let Some(providers) = providers {
            providers.0.shutdown().unwrap();
            // providers.1.shutdown()?;
        }
    })?;
    {
        use futures::future::{FutureExt, select_all};
        use tokio::signal::unix::{SignalKind, signal};

        // Create futures for SIGINT, SIGTERM, and SIGKILL
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        // Wait for any of the signals
        let sigint_fut = sigint.recv().boxed();
        let sigterm_fut = sigterm.recv().boxed();

        let _ = select_all([sigint_fut, sigterm_fut]).await;
        log::info!("Received signal, stopping...");
    }
    Ok(())
}
