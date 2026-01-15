pub(crate) mod config;
pub(crate) mod connection;
pub(crate) mod bedrock_proxy;
pub(crate) mod crossplay;
pub(crate) mod error;
pub(crate) mod inspect;
pub(crate) mod logging;
pub(crate) mod lure;
pub(crate) mod metrics;
pub(crate) mod packet;
pub(crate) mod router;
pub(crate) mod telemetry;
pub(crate) mod threat;
pub(crate) mod utils;

use std::{env, error::Error, io::ErrorKind, net::SocketAddr};

use config::LureConfig;
use lure::Lure;

use crate::{
    config::{LureConfigLoadError, ProxySigningKey},
    router::RouterInstance,
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

    let bedrock_config = config.clone();
    let lure = leak(Lure::new(config));
    lure.sync_routes_from_config().await?;

    if let Ok(value) = env::var("LURE_BEDROCK_BIND") {
        let bind = value.trim();
        if !bind.is_empty() {
            match bind.parse::<SocketAddr>() {
                Ok(addr) => {
                    let bedrock_router = leak(RouterInstance::new());
                    bedrock_router.set_instance_name(format!("{}-bedrock", bedrock_config.inst));
                    match bedrock_config.default_routes() {
                        Ok(routes) => {
                            for route in routes {
                                bedrock_router.apply_route(route).await;
                            }
                            let crossplay = lure.crossplay_supervisor();
                            spawn_named("Bedrock proxy", async move {
                                if let Err(err) =
                                    bedrock_proxy::start(addr, bedrock_router, crossplay).await
                                {
                                    log::error!("bedrock proxy failed: {err}");
                                }
                            })?;
                        }
                        Err(err) => {
                            log::error!("Failed to load routes for bedrock proxy: {err}");
                        }
                    }
                }
                Err(err) => {
                    log::error!("Invalid LURE_BEDROCK_BIND value '{bind}': {err}");
                }
            }
        }
    }

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
