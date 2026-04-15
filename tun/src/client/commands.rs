use std::path::PathBuf;

use anyhow::Context;
use log::{error, info, warn};

use super::{
    cli::{ConfigArgs, ConfigCommand, InstallArgs, SignArgs},
    config::{
        HumanDuration, TunConfig, TunnelEntry, copy_self_to, default_config_path, find_config_path,
        home_dir, load_config, load_or_default_config, parse_endpoints, parse_hex_exact,
        parse_human_duration, pid_file_path, save_config, xdg_config_home,
    },
};
use crate::Intent;

pub(super) fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    // Copy binary to ~/.local/bin/minitun (user) or /usr/local/bin/minitun (system)
    let bin_dest = if args.system {
        PathBuf::from("/usr/local/bin/minitun")
    } else {
        home_dir()
            .ok_or_else(|| anyhow::anyhow!("HOME not set"))?
            .join(".local")
            .join("bin")
            .join("minitun")
    };
    if let Err(err) = copy_self_to(&bin_dest) {
        error!("failed to install binary: {err}");
        return Err(err);
    }

    let path = default_config_path()?;
    let mut config = load_or_default_config(&path)?;

    // Parse endpoints
    let all_endpoints: Vec<String> = args
        .endpoints
        .iter()
        .flat_map(|e| parse_endpoints(e))
        .collect();

    // Merge tokens
    if !args.tokens.is_empty() {
        let mut parsed_tokens = Vec::new();
        for token_str in &args.tokens {
            TunConfig::from_entry(&TunnelEntry {
                endpoints: all_endpoints.clone(),
                token: token_str.clone(),
                proxy_protocol: false,
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            parsed_tokens.push((token_str.clone(), all_endpoints.clone()));
        }

        for (token, endpoints) in parsed_tokens {
            // Find and update existing, or append
            let parts: Vec<&str> = token.split(':').collect();
            if parts.len() != 2 {
                warn!("skipping token during install (invalid format): token={token}");
                continue;
            }
            let key_id = match parse_hex_exact::<8>(parts[0]) {
                Ok(key_id) => key_id,
                Err(parse_err) => {
                    warn!(
                        "skipping token during install (invalid key_id): token={token} err={parse_err}"
                    );
                    continue;
                }
            };

            let mut found = false;
            for entry in &mut config.tunnels {
                match TunConfig::from_entry(entry) {
                    Ok(tc) => {
                        if tc.key_id == key_id {
                            entry.endpoints = endpoints.clone();
                            found = true;
                            break;
                        }
                    }
                    Err(decode_err) => {
                        warn!(
                            "skipping existing tunnel entry during install merge: token={} err={decode_err}",
                            entry.token
                        );
                    }
                }
            }
            if !found {
                config.tunnels.push(TunnelEntry {
                    endpoints: endpoints.clone(),
                    token: token.clone(),
                    proxy_protocol: false,
                });
            }
        }
    }

    // Merge map entries
    if let (Some(name), Some(addr)) = (&args.map_name, &args.map_addr) {
        config.map.insert(name.clone(), addr.clone());
    }

    // Set strict mode if flag given
    if args.strict {
        config.strict = true;
    }

    // Set reconnect if given
    if let Some(dur_str) = &args.reconnect {
        config.reconnect =
            HumanDuration(parse_human_duration(dur_str).context("invalid reconnect duration")?);
    }

    save_config(&path, &config)?;
    info!("config saved to: {}", path.display());

    Ok(())
}

pub(super) fn run_reload() -> anyhow::Result<()> {
    let pid_path = pid_file_path()?;
    let raw = std::fs::read_to_string(&pid_path)
        .with_context(|| format!("could not read PID file: {}", pid_path.display()))?;
    let pid: u32 = raw
        .trim()
        .parse()
        .context("PID file contains invalid number")?;
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("failed to send SIGHUP to pid {pid}: {err}");
        }
        info!("sent SIGHUP to minitun pid={pid}");
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("reload is not supported on this platform");
    }
    Ok(())
}

pub(super) fn run_update() -> anyhow::Result<()> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        other => anyhow::bail!("unsupported OS for auto-update: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => anyhow::bail!("unsupported arch for auto-update: {other}"),
    };

    let url =
        format!("https://github.com/illnet/mach/releases/latest/download/minitun-{os}-{arch}");
    info!("downloading update from {url}");

    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("minitun/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client.get(&url).send()?;
    if !response.status().is_success() {
        anyhow::bail!("update download failed: HTTP {}", response.status());
    }
    let bytes = response.bytes()?;

    let current_exe = std::env::current_exe()?;
    let tmp_path = current_exe.with_extension("update.tmp");
    std::fs::write(&tmp_path, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }

    std::fs::rename(&tmp_path, &current_exe)
        .context("failed to replace current exe with updated binary")?;

    info!("minitun updated successfully; restart to use new version");
    Ok(())
}

pub(super) fn run_config(args: ConfigArgs) -> anyhow::Result<()> {
    match args.command {
        ConfigCommand::Show => {
            let path = find_config_path().ok_or_else(|| anyhow::anyhow!("no config file found"))?;
            let cfg = load_config(&path)?;
            println!("{}", toml::to_string_pretty(&cfg)?);
        }
        ConfigCommand::AddTunnel(a) => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path)?;
            let endpoints = a
                .endpoints
                .iter()
                .flat_map(|e| parse_endpoints(e))
                .collect::<Vec<_>>();
            // Validate token before inserting.
            TunConfig::from_entry(&TunnelEntry {
                endpoints: endpoints.clone(),
                token: a.token.clone(),
                proxy_protocol: false,
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            cfg.tunnels.push(TunnelEntry {
                endpoints,
                token: a.token,
                proxy_protocol: false,
            });
            save_config(&path, &cfg)?;
            info!("tunnel added; {} total", cfg.tunnels.len());
        }
        ConfigCommand::RemoveTunnel { index_or_key } => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path)?;
            if let Ok(idx) = index_or_key.parse::<usize>() {
                if idx >= cfg.tunnels.len() {
                    anyhow::bail!("index {idx} out of range (have {})", cfg.tunnels.len());
                }
                cfg.tunnels.remove(idx);
            } else {
                let before = cfg.tunnels.len();
                cfg.tunnels.retain(|e| {
                    e.token
                        .split(':')
                        .next()
                        .map(|k| !k.starts_with(&index_or_key))
                        .unwrap_or(true)
                });
                let removed = before - cfg.tunnels.len();
                if removed == 0 {
                    anyhow::bail!("no tunnel matched key_id prefix: {index_or_key}");
                }
            }
            save_config(&path, &cfg)?;
        }
        ConfigCommand::AddMap { name, addr } => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path)?;
            cfg.map.insert(name, addr);
            save_config(&path, &cfg)?;
        }
        ConfigCommand::RemoveMap { name } => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path)?;
            if cfg.map.remove(&name).is_none() {
                anyhow::bail!("map entry '{name}' not found");
            }
            save_config(&path, &cfg)?;
        }
    }
    Ok(())
}

pub(super) fn run_systemd_gensys(
    user: bool,
    system: bool,
    name: Option<String>,
) -> anyhow::Result<()> {
    if system && user {
        anyhow::bail!("choose one: --user or --system");
    }
    let scope_user = user;

    let normalized_service = name
        .as_deref()
        .map(|n| {
            let basename = n
                .trim()
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("minitun")
                .trim();
            let normalized = basename.strip_suffix(".service").unwrap_or(basename);
            if normalized.is_empty() {
                "minitun".to_string()
            } else {
                normalized.to_string()
            }
        })
        .unwrap_or_else(|| "minitun".to_string());

    let unit_dir = if scope_user {
        let cfg_home = xdg_config_home()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir (HOME required)"))?;
        cfg_home.join("systemd").join("user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    let exe = std::env::current_exe()?;
    let config_path = default_config_path()?;
    let service_file = if normalized_service.ends_with(".service") {
        normalized_service.clone()
    } else {
        format!("{normalized_service}.service")
    };

    let working_dir = if scope_user { "~" } else { "/etc" };

    // Generate unit file content.
    let unit_content = format!(
        r#"[Unit]
Description=Minitun tunnel agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} run
WorkingDirectory={working_dir}
Restart=always
RestartSec=2

[Install]
WantedBy={wanted_by}
"#,
        exe = exe.display(),
        working_dir = working_dir,
        wanted_by = if scope_user {
            "default.target"
        } else {
            "multi-user.target"
        },
    );

    let unit_path = unit_dir.join(&service_file);

    println!("# Generated systemd unit file for: {}", normalized_service);
    println!("# Install location:");
    println!("#   User:   {}", unit_path.display());
    println!("#   System: /etc/systemd/system/{}", service_file);
    println!();
    println!("# Config file location: {}", config_path.display());
    println!();
    println!("{}", unit_content);
    println!();
    println!("# To install:");
    println!("# 1. Copy the above unit file to the appropriate location");
    println!(
        "# 2. Run: systemctl{} daemon-reload",
        if scope_user { " --user" } else { "" }
    );
    println!(
        "# 3. Run: systemctl{} enable --now {}",
        if scope_user { " --user" } else { "" },
        service_file
    );

    Ok(())
}

pub(super) fn run_sign(args: SignArgs) -> anyhow::Result<()> {
    let intent = match args.intent.as_str() {
        "listen" => Intent::Listen,
        "connect" => Intent::Connect,
        "beacon" => Intent::Beacon,
        other => anyhow::bail!("invalid intent {other}"),
    };

    let parts: Vec<&str> = args.token.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("token format: key_id:secret (both hex-encoded)");
    }
    let key_id = parse_hex_exact::<8>(parts[0]).map_err(|e| anyhow::anyhow!("{e}"))?;
    let secret = parse_hex_exact::<32>(parts[1]).map_err(|e| anyhow::anyhow!("{e}"))?;

    let timestamp = args.timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    });

    let session = match intent {
        Intent::Listen | Intent::Beacon => None,
        Intent::Connect => {
            let s = args
                .session
                .ok_or_else(|| anyhow::anyhow!("--session is required for connect intent"))?;
            Some(parse_hex_exact::<32>(&s).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        Intent::Forward => anyhow::bail!("forward intent is not supported by `sign`"),
    };

    let hmac = crate::compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        intent,
        session.as_ref(),
        None,
        0,
        None,
    );

    println!("version={}", crate::VERSION);
    println!("intent={}", args.intent);
    println!("key_id={}", hex::encode(key_id));
    println!("timestamp={timestamp}");
    if let Some(s) = session {
        println!("session={}", hex::encode(s));
    }
    println!("hmac={}", hex::encode(hmac));

    Ok(())
}
