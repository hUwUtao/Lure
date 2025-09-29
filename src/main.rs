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

use std::{env, error::Error};

use anyhow::anyhow;
use config::LureConfig;
use lure::Lure;

use crate::{
    config::LureConfigLoadError,
    telemetry::{oltp::init_meter, process::ProcessMetricsService},
    utils::leak,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = dotenvy::dotenv();
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
    let config_file_path = config_file
        .to_str()
        .ok_or(anyhow!("Failed to get config file path"))?;

    let config = match LureConfig::load(config_file_path) {
        Ok(config) => {
            // Save config to fill missing fields
            let _ = config.save(config_file_path);
            Ok(config)
        }
        Err(error) => {
            match error {
                LureConfigLoadError::Io(_) => {
                    // If config loading fails we generate a default config
                    let default_config = LureConfig::default();
                    // Save the config to disk
                    let _ = default_config.save(config_file_path);
                    Ok(default_config)
                }
                LureConfigLoadError::Parse(parse_error) => Err(parse_error),
            }
        }
    }?;

    let pmt = leak(ProcessMetricsService::new());
    pmt.start();

    let lure = leak(Lure::new(config));
    lure.start().await?;
    if let Some(providers) = providers {
        providers.0.shutdown()?;
        // providers.1.shutdown()?;
    }
    Ok(())
}
