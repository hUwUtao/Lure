use std::{
    collections::HashMap,
    fs::{self, File},
    io::prelude::*,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::router::{Route, RouteAttr, RouteFlags};

const DEFAULT_ROUTE_ID_BASE: u64 = u64::MAX - u32::MAX as u64;

/// Top-level configuration for the application, loaded from a TOML file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LureConfig {
    /// Unique instance name or identifier.
    #[serde(default = "default_inst")]
    pub inst: String,

    /// Socket address to bind to, e.g. "0.0.0.0:25565".
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Enable or disable proxy protocol support.
    #[serde(default, rename = "proxy_procol")]
    pub proxy_protocol: bool,

    /// Maximum concurrent downstream connections.
    #[serde(default = "default_max_conn")]
    pub max_conn: u32,

    /// Cooldown interval (seconds) applied to connection rate limiter.
    #[serde(default)]
    pub cooldown: u64,

    /// Localized string map used for placeholder responses.
    #[serde(default)]
    pub strings: HashMap<Box<str>, Box<str>>,

    /// Default, statically-configured routes.
    #[serde(default)]
    pub route: Vec<RouteConfig>,

    #[serde(flatten)]
    pub other_fields: HashMap<String, toml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct RouteConfig {
    /// Optional single matcher helper.
    pub matcher: Option<String>,
    /// Matcher list; combined with `matcher` if present.
    pub matchers: Vec<String>,
    /// Optional single endpoint helper.
    pub endpoint: Option<String>,
    /// Endpoint list; combined with `endpoint` if present.
    pub endpoints: Vec<String>,
    /// Route priority.
    pub priority: i32,
    /// Additional flags to apply.
    pub flags: Option<RouteFlagsConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct RouteFlagsConfig {
    pub disabled: bool,
    pub proxy_protocol: bool,
    pub cache_query: bool,
    pub override_query: bool,
    pub preserve_host: bool,
}

fn default_inst() -> String {
    "main".to_string()
}

fn default_bind() -> String {
    "0.0.0.0:25577".to_string()
}

fn default_max_conn() -> u32 {
    65535
}

impl Default for LureConfig {
    fn default() -> Self {
        Self {
            inst: default_inst(),
            bind: default_bind(),
            proxy_protocol: false,
            max_conn: default_max_conn(),
            cooldown: 3,
            strings: HashMap::new(),
            route: Vec::new(),
            other_fields: HashMap::new(),
        }
    }
}

impl LureConfig {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self, LureConfigLoadError> {
        let raw = fs::read_to_string(path).map_err(LureConfigLoadError::Io)?;
        let config: Self = toml::from_str(&raw).map_err(LureConfigLoadError::Parse)?;

        for field in &config.other_fields {
            println!(
                "Unknown configuration '{}' with value {:?}",
                field.0, field.1
            );
        }

        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let config_str = toml::to_string(&self)?;
        let mut file = File::create(path)?;
        file.write_all(config_str.as_bytes())?;
        Ok(())
    }

    pub fn default_routes(&self) -> anyhow::Result<Vec<Route>> {
        self.route
            .iter()
            .enumerate()
            .map(|(idx, cfg)| cfg.to_route(idx))
            .collect()
    }
}

impl RouteConfig {
    fn to_route(&self, offset: usize) -> anyhow::Result<Route> {
        let mut matchers: Vec<String> = self.matchers.clone();
        if let Some(single) = &self.matcher {
            matchers.push(single.clone());
        }
        if matchers.is_empty() {
            anyhow::bail!("route entry {offset} missing matchers");
        }

        let mut endpoint_specs: Vec<String> = self.endpoints.clone();
        if let Some(single) = &self.endpoint {
            endpoint_specs.push(single.clone());
        }
        if endpoint_specs.is_empty() {
            anyhow::bail!("route entry {offset} missing endpoints");
        }

        let mut endpoints = Vec::with_capacity(endpoint_specs.len());
        let mut endpoint_hosts = Vec::with_capacity(endpoint_specs.len());
        for spec in endpoint_specs {
            let spec = spec.trim();
            let host_hint = extract_endpoint_host(spec)?;
            match SocketAddr::from_str(spec) {
                Ok(addr) => {
                    endpoints.push(addr);
                    endpoint_hosts.push(Some(host_hint.clone()));
                }
                Err(_) => {
                    let mut resolved = spec
                        .to_socket_addrs()
                        .map_err(|err| anyhow::anyhow!("invalid endpoint '{spec}': {err}"))?;
                    let mut found = false;
                    for addr in resolved.by_ref() {
                        endpoints.push(addr);
                        endpoint_hosts.push(Some(host_hint.clone()));
                        found = true;
                    }
                    if !found {
                        anyhow::bail!("endpoint '{spec}' resolved to no addresses");
                    }
                }
            }
        }

        if offset >= u32::MAX as usize {
            anyhow::bail!("route entry index {offset} exceeds reserved id range");
        }

        Ok(Route {
            id: DEFAULT_ROUTE_ID_BASE + offset as u64,
            zone: u64::MAX,
            priority: self.priority,
            flags: self
                .flags
                .as_ref()
                .map(RouteFlagsConfig::to_attr)
                .unwrap_or_default(),
            matchers,
            endpoints,
            endpoint_hosts,
        })
    }
}

impl RouteFlagsConfig {
    fn to_attr(&self) -> RouteAttr {
        let mut attr = RouteAttr::default();
        if self.disabled {
            attr.set_flag(RouteFlags::Disabled);
        }
        if self.proxy_protocol {
            attr.set_flag(RouteFlags::ProxyProtocol);
        }
        if self.cache_query {
            attr.set_flag(RouteFlags::CacheQuery);
        }
        if self.override_query {
            attr.set_flag(RouteFlags::OverrideQuery);
        }
        if self.preserve_host {
            attr.set_flag(RouteFlags::PreserveHost);
        }
        attr
    }
}

fn extract_endpoint_host(spec: &str) -> anyhow::Result<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("endpoint specification is empty");
    }
    if let Some(start) = spec.strip_prefix('[') {
        let end = start
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("endpoint '{spec}' missing closing bracket"))?;
        let host = &start[..end];
        return Ok(host.to_string());
    }
    if let Some(idx) = spec.rfind(':') {
        if idx == 0 {
            anyhow::bail!("endpoint '{spec}' missing hostname before port");
        }
        return Ok(spec[..idx].to_string());
    }
    anyhow::bail!("endpoint '{spec}' missing port separator");
}

#[derive(Debug, thiserror::Error)]
pub enum LureConfigLoadError {
    #[error("Could not open config")]
    Io(#[from] std::io::Error),
    #[error("Could not parse")]
    Parse(#[from] toml::de::Error),
}
