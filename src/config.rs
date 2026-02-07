use std::{
    collections::HashMap,
    fs::{self, File},
    io::prelude::*,
    path::PathBuf,
    sync::Arc,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use log::warn;
use serde::{Deserialize, Serialize, Serializer};

use crate::router::{AuthMode, Endpoint, Route, RouteAttr, RouteFlags};

const DEFAULT_ROUTE_ID_BASE: u64 = u64::MAX - u32::MAX as u64;

#[derive(Debug, Clone)]
pub struct ProxySigningKey(Vec<u8>);

impl ProxySigningKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_base64(value: &str) -> Result<Self, base64::DecodeError> {
        STANDARD.decode(value.trim()).map(Self)
    }
}

impl Serialize for ProxySigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProxySigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ProxySigningKeyRepr {
            Base64(String),
            Raw(Vec<u8>),
        }

        let repr = ProxySigningKeyRepr::deserialize(deserializer)?;
        let bytes = match repr {
            ProxySigningKeyRepr::Base64(value) => match ProxySigningKey::from_base64(&value) {
                Ok(key) => return Ok(key),
                Err(err) => {
                    warn!("proxy_signing_key is not valid base64: {err}");
                    Vec::new()
                }
            },
            ProxySigningKeyRepr::Raw(bytes) => bytes,
        };
        Ok(ProxySigningKey(bytes))
    }
}

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

    /// Optional Ed25519 private key (base64 string or byte array) for signing proxy headers.
    #[serde(default)]
    pub proxy_signing_key: Option<ProxySigningKey>,

    /// Maximum concurrent downstream connections.
    #[serde(default = "default_max_conn")]
    pub max_conn: u32,

    /// Cooldown interval (seconds) applied to connection rate limiter.
    #[serde(default)]
    pub cooldown: u64,

    /// Localized string map used for placeholder responses.
    #[serde(default)]
    pub strings: HashMap<Box<str>, Arc<str>>,

    /// Tunnel configuration (token registry)
    #[serde(default)]
    pub tunnel: TunnelConfig,

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
    /// Optional tunnel token (hex or base64, 32 bytes).
    pub tunnel_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct RouteFlagsConfig {
    pub disabled: bool,
    pub proxy_protocol: bool,
    pub cache_query: bool,
    pub override_query: bool,
    pub preserve_host: bool,
    pub tunnel: bool,
    /// Authentication mode: "public", "protected", "restricted"
    pub auth_mode: String,
    /// For auth_mode = "restricted", list of allowed token key_ids
    pub allowed_tokens: Vec<String>,
}

/// Tunnel configuration for HMAC token registry
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct TunnelConfig {
    /// List of registered tokens
    pub token: Vec<TokenEntry>,
}

/// Individual token entry for tunnel authentication
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenEntry {
    /// 8-byte key ID (16 hex characters)
    pub key_id: String,
    /// 32-byte secret key (64 hex characters or base64)
    pub secret: String,
    /// Optional human-readable name
    pub name: Option<String>,
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

fn default_auth_mode() -> String {
    "protected".to_string()
}

impl Default for LureConfig {
    fn default() -> Self {
        Self {
            inst: default_inst(),
            bind: default_bind(),
            proxy_protocol: false,
            proxy_signing_key: None,
            max_conn: default_max_conn(),
            cooldown: 3,
            strings: HashMap::new(),
            tunnel: TunnelConfig::default(),
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

    pub fn string_value(&self, key: &str) -> Arc<str> {
        self.strings
            .get(key)
            .cloned()
            .unwrap_or(Arc::from(format!("{key}-is-not-written")))
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

        let mut endpoints: Vec<Endpoint> = Vec::with_capacity(endpoint_specs.len());
        for spec in endpoint_specs {
            let trimmed = spec.trim();
            if trimmed.is_empty() {
                anyhow::bail!("route entry {offset} contains empty endpoint");
            }
            let destination = Endpoint::parse_with_default(trimmed, 25565).map_err(|err| {
                anyhow::anyhow!("invalid endpoint '{trimmed}' in route {offset}: {err}")
            })?;
            endpoints.push(destination);
        }

        if offset >= u32::MAX as usize {
            anyhow::bail!("route entry index {offset} exceeds reserved id range");
        }

        let tunnel_token =
            if let Some(token) = &self.tunnel_token {
                Some(parse_tunnel_token(token).map_err(|err| {
                    anyhow::anyhow!("invalid tunnel token for route {offset}: {err}")
                })?)
            } else {
                None
            };

        let (flags, auth_mode) = if let Some(flags_cfg) = &self.flags {
            let attr = flags_cfg.to_attr();
            let auth_mode = flags_cfg.parse_auth_mode(offset)?;
            (attr, auth_mode)
        } else {
            (RouteAttr::default(), AuthMode::default())
        };

        Ok(Route {
            id: DEFAULT_ROUTE_ID_BASE + offset as u64,
            zone: u64::MAX,
            priority: self.priority,
            flags,
            tunnel_token,
            auth_mode,
            matchers,
            endpoints,
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
        if self.tunnel {
            attr.set_flag(RouteFlags::Tunnel);
        }
        attr
    }

    fn parse_auth_mode(&self, route_offset: usize) -> anyhow::Result<AuthMode> {
        match self.auth_mode.as_str() {
            "public" => Ok(AuthMode::Public),
            "protected" => Ok(AuthMode::Protected),
            "restricted" => {
                if self.allowed_tokens.is_empty() {
                    anyhow::bail!(
                        "route entry {route_offset} with auth_mode=\"restricted\" must have allowed_tokens"
                    );
                }
                let mut allowed = Vec::with_capacity(self.allowed_tokens.len());
                for token_str in &self.allowed_tokens {
                    let key_id = parse_key_id_8(token_str).map_err(|err| {
                        anyhow::anyhow!(
                            "invalid key_id in allowed_tokens for route {route_offset}: {err}"
                        )
                    })?;
                    allowed.push(key_id);
                }
                Ok(AuthMode::Restricted {
                    allowed_tokens: allowed,
                })
            }
            other => anyhow::bail!(
                "route entry {route_offset} has invalid auth_mode \"{}\", must be \"public\", \"protected\", or \"restricted\"",
                other
            ),
        }
    }
}

fn parse_tunnel_token(token: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = token.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
            out[i] = byte;
        }
        return Ok(out);
    }
    let decoded = STANDARD.decode(trimmed)?;
    if decoded.len() != 32 {
        anyhow::bail!("expected 32 bytes, got {}", decoded.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn parse_key_id_8(key_id_str: &str) -> anyhow::Result<[u8; 8]> {
    let trimmed = key_id_str.trim();
    if trimmed.len() != 16 {
        anyhow::bail!("key_id must be 16 hex characters, got {}", trimmed.len());
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("key_id must be hex-encoded");
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
        out[i] = byte;
    }
    Ok(out)
}

fn parse_secret_32(secret_str: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = secret_str.trim();
    // Try hex first
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
            out[i] = byte;
        }
        return Ok(out);
    }
    // Try base64
    let decoded = STANDARD.decode(trimmed)?;
    if decoded.len() != 32 {
        anyhow::bail!(
            "secret must be 64-char hex or valid base64 for 32 bytes, got {}",
            decoded.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum LureConfigLoadError {
    #[error("Could not open config")]
    Io(#[from] std::io::Error),
    #[error("Could not parse")]
    Parse(#[from] toml::de::Error),
}
