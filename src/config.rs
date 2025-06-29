use std::fs::File;
use std::io::prelude::*;
use std::{collections::HashMap, fs};

use serde::{Deserialize, Serialize};
// v2

/// Top-level configuration for the application, loaded from a TOML file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LureConfig {
    /// Unique instance name or identifier
    pub inst: String,

    /// Socket address to bind to, e.g. "0.0.0.0:25565"
    pub bind: String,

    /// Enable or disable proxy protocol support
    #[serde(rename = "proxy_procol")]
    pub proxy_protocol: bool,

    /// Cache-related parameters
    pub cache: CacheConfig,

    /// Threat protection and rate-limiting settings
    ///
    /// This section defines the L7 threat model controls:
    /// - `ban`: total violation count before automatically banning an IP
    /// - `stall`: thresholds for detecting login spam that stalls backend
    /// - `hang`: inter-packet timeout thresholds to catch hanging connections
    pub threat: ThreatConfig,

    /// Connection limit semaphore thresholds
    pub semaphore: SemaphoreConfig,

    /// RPC and metrics endpoint configuration
    pub control: ControlConfig,

    /// Mapping of route patterns to upstream endpoints
    pub routes: HashMap<String, RouteConfig>,

    #[serde(flatten)]
    pub other_fields: HashMap<String, toml::value::Value>,
}

/// Configuration for cache durations (in milliseconds)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    /// TTL for query cache
    pub query: u64,

    /// TTL for intelligence data cache
    pub inteligence: u64,
}

/// Top-level threat protection config
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatConfig {
    /// Number of violations before banning an IP permanently
    ///
    /// Used to enforce automated blacklisting after repeated abuse.
    pub ban: u32,

    /// Stall detection: high-volume login attempts in a short window
    pub stall: StallConfig,

    /// Hang detection: prolonged or silent connections
    pub hang: HangConfig,
}

/// Delay selective client whilst login to counterattack.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StallConfig {
    /// Killswitch
    pub enable: bool,

    /// Time should be delayed for selective client
    pub login: u32,
}

/// Timeout checks between packets to avoid hangs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HangConfig {
    /// Query timeout threshold (seconds)
    /// If no full packet arrives within this time, consider the connection hung.
    pub query: u64,

    /// Login timeout threshold (seconds)
    pub login: u64,

    /// Transport-level timeout threshold (seconds)
    pub transport: u64,
}

/// Semaphore thresholds for active connections
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemaphoreConfig {
    /// Soft limit for active sockets
    pub acceptable: u32,

    /// Critical ratio (0.0 - 1.0) for raising alerts or shedding load
    pub critical: f32,
}

/// Control endpoints for RPC and metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlConfig {
    /// URL for RPC calls (subscribe/push socket control)
    pub rpc: String,

    /// URL for Prometheus metrics ingestion
    pub metrics: String,
}

/// Configuration for a single route pattern
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    /// List of backend destinations (host:port)
    pub dest: Vec<String>,

    /// Use HAProxy protocol when forwarding
    pub haproto: bool,

    /// Apply network masking rules to this route
    pub mask: bool,
}

impl Default for LureConfig {
    fn default() -> Self {
        Self {
            inst: "main".to_string(),
            bind: "0.0.0.0:25577".to_string(),
            proxy_protocol: false,
            cache: CacheConfig {
                query: 5000,
                inteligence: 60000,
            },
            threat: ThreatConfig {
                ban: 10,
                stall: StallConfig {
                    enable: false,
                    login: 1000,
                },
                hang: HangConfig {
                    query: 100,
                    login: 1000,
                    transport: 30000,
                },
            },
            semaphore: SemaphoreConfig {
                acceptable: 65535,
                critical: 0.9,
            },
            control: ControlConfig {
                rpc: "".to_string(),
                metrics: "".to_string(),
            },
            routes: Default::default(),
            other_fields: Default::default(),
        }
    }
}

impl LureConfig {
    pub fn load(path: &str) -> anyhow::Result<Self, LureConfigLoadError> {
        let raw = fs::read_to_string(path).map_err(|err| LureConfigLoadError::Io(err))?;
        let config: Self = toml::from_str(&raw).map_err(|err| LureConfigLoadError::Parse(err))?;

        for field in &config.other_fields {
            println!(
                "Unknown configuration '{}' with value {:?}",
                field.0, field.1
            );
        }

        Ok(config)
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let config_str = toml::to_string(&self)?;
        let mut file = File::create(path)?;
        file.write_all(config_str.as_bytes())?;
        Ok(())
    }
}

pub enum LureConfigLoadError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}
