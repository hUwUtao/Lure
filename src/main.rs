use std::{env, error::Error, io::ErrorKind};

use lure::{
    config::{LureConfigLoadError, ProxySigningKey},
    config::LureConfig,
    lure::Lure,
    sock::{BackendKind, backend_selection},
    telemetry::{oltp::init_meter, process::ProcessMetricsService},
    utils::{leak, spawn_named},
};

fn main() -> Result<(), Box<dyn Error>> {
    let _ = dotenvy::dotenv();
    console_subscriber::init();
    #[cfg(debug_assertions)]
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    #[cfg(not(debug_assertions))]
    env_logger::init();

    let backend = backend_selection();
    match backend.kind {
        BackendKind::Uring => {
            log::info!("socket backend: tokio-uring ({})", backend.reason);
            net::sock::uring::start(async {
                let local = tokio::task::LocalSet::new();
                local.run_until(run()).await
            })
        }
        BackendKind::Epoll => {
            log::info!("socket backend: epoll ({})", backend.reason);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(run()))
        }
        BackendKind::Tokio => {
            if backend.reason.contains("init failed") {
                log::warn!("socket backend: tokio ({})", backend.reason);
            } else {
                log::info!("socket backend: tokio ({})", backend.reason);
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(run()))
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let providers = if dotenvy::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        Some((init_meter(), 0u8))
    } else {
        None
    };

    let current_dir = env::current_dir()?;
    let config_file = current_dir.join("settings.toml");

    let mut should_save = false;
    let mut config = match LureConfig::load(&config_file) {
        Ok(config) => config,
        Err(LureConfigLoadError::Io(io)) => {
            if io.kind() == ErrorKind::NotFound {
                should_save = true;
                LureConfig::default()
            } else {
                return Err(io.into());
            }
        }
        Err(LureConfigLoadError::Parse(parse_error)) => return Err(parse_error.into()),
    };
    apply_proxy_signing_key(&mut config);
    if should_save {
        config.save(&config_file)?;
    }

    let pmt = leak(ProcessMetricsService::new());
    pmt.start();

    let lure = leak(Lure::new(config));
    lure.sync_routes_from_config().await?;

    let reload_path = config_file.clone();
    let reload_lure = lure;
    spawn_named("Reload handler", async move {
        use tokio::signal::unix::{SignalKind, signal};

        // SIGCONT=18
        let mut sigcont = match signal(SignalKind::from_raw(18)) {
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

fn apply_proxy_signing_key(config: &mut LureConfig) {
    if let Ok(value) = env::var("LURE_PROXY_SIGNING_KEY") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        match ProxySigningKey::from_base64(trimmed) {
            Ok(key) => {
                config.proxy_signing_key = Some(key);
                log::info!("proxy signing key loaded from env");
            }
            Err(err) => {
                log::warn!("LURE_PROXY_SIGNING_KEY is not valid base64: {err}");
            }
        }
        return;
    }

    if config.proxy_signing_key.is_some() {
        return;
    }

    let mut seed = [0u8; 32];
    if let Err(err) = getrandom::fill(&mut seed) {
        log::warn!("failed to generate proxy signing key: {err}");
        return;
    }
    config.proxy_signing_key = Some(ProxySigningKey::from_bytes(seed.to_vec()));
    log::info!("generated ephemeral proxy signing key");
}
