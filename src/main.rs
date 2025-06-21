mod config;
mod connection;
mod lure;
pub(crate) mod packet;
mod router;
pub(crate) mod telemetry;
mod utils;

use anyhow::anyhow;
use std::env;
use std::error::Error;

use config::LureConfig;
use lure::Lure;

use crate::config::LureConfigLoadError;
use crate::telemetry::init_meter_provider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    femme::start();
    let meter_provider = init_meter_provider()?;

    let current_dir = env::current_dir()?;
    let config_file = current_dir.join("settings.toml");
    let config_file_path = config_file
        .to_str()
        .ok_or(anyhow!("Failed to get config file path"))?;

    println!("{}", config_file_path);

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
    };

    let lure = Box::leak(Box::new(Lure::new(config?)));
    lure.start().await?;
    meter_provider.shutdown()?;
    Ok(())
}
