use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use clap::{Args, Parser, Subcommand};
use log::{error, info};
use tun::{AgentHello, Intent, ServerMsg};

#[derive(Parser)]
#[command(name = "tunure")]
#[command(about = "Lure tunnel agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the tunnel agent (register, then serve session offers)
    Agent(AgentArgs),
    /// Compute a valid HMAC signature for a hello message (development helper)
    Sign(SignArgs),
    /// Install/uninstall tunure as a systemd service
    Systemd(SystemdArgs),
}

#[derive(Args)]
struct AgentArgs {
    /// Proxy address (host:port)
    #[arg(env = "LURE_TUN_ENDPOINT")]
    proxy: String,

    /// Authentication token (format: key_id:secret, both hex-encoded)
    #[arg(short, long, env = "LURE_TUN_TOKEN")]
    token: Option<String>,
}

#[derive(Args)]
struct SignArgs {
    /// Token (format: key_id:secret, both hex-encoded)
    #[arg(short, long, env = "LURE_TUN_TOKEN")]
    token: String,

    /// Intent to sign for
    #[arg(long, value_parser = ["listen", "connect"])]
    intent: String,

    /// Unix timestamp (seconds). If omitted, uses current time.
    #[arg(long)]
    timestamp: Option<u64>,

    /// Session token for connect intent (64 hex chars, 32 bytes)
    #[arg(long)]
    session: Option<String>,
}

#[derive(Args)]
struct SystemdArgs {
    #[command(subcommand)]
    command: SystemdCommand,
}

#[derive(Subcommand)]
enum SystemdCommand {
    /// Install and enable a tunure-agent systemd unit
    Install(SystemdInstallArgs),
    /// Disable and remove the tunure-agent systemd unit
    Uninstall(SystemdUninstallArgs),
}

#[derive(Args)]
struct SystemdInstallArgs {
    /// Proxy address (host:port) for the agent to connect to.
    ///
    /// You can also set LURE_TUN_ENDPOINT.
    #[arg(long, env = "LURE_TUN_ENDPOINT")]
    endpoint: String,

    /// Authentication token (format: key_id:secret, both hex-encoded).
    ///
    /// You can also set LURE_TUN_TOKEN.
    #[arg(short, long, env = "LURE_TUN_TOKEN")]
    token: Option<String>,

    /// Install as a per-user service (default).
    #[arg(long)]
    user: bool,

    /// Install as a system-wide service (writes to /etc/systemd/system).
    #[arg(long)]
    system: bool,

    /// Override the service name (without .service).
    ///
    /// Default is tunure-agent-<key_id>.
    #[arg(long)]
    name: Option<String>,

    /// Copy the current tunure binary to a stable path and use it for the service.
    #[arg(long, default_value_t = true)]
    install_bin: bool,

    /// Where to install the tunure binary to (overrides default).
    ///
    /// Defaults:
    /// - user:   ~/.local/bin/tunure
    /// - system: /usr/local/bin/tunure
    #[arg(long)]
    bin_path: Option<String>,

    /// Extra RUST_LOG for the service (default: info)
    #[arg(long, default_value = "info")]
    rust_log: String,

    /// After writing the unit, attempt to `systemctl enable --now`.
    #[arg(long, default_value_t = true)]
    enable_now: bool,
}

#[derive(Args)]
struct SystemdUninstallArgs {
    /// Uninstall from the per-user service directory (~/.config/systemd/user).
    #[arg(long)]
    user: bool,

    /// Uninstall from the system service directory (/etc/systemd/system).
    #[arg(long)]
    system: bool,

    /// Service name to uninstall (without .service).
    #[arg(long)]
    name: String,
}

struct TunConfig {
    key_id: [u8; 8],
    secret: [u8; 32],
}

fn parse_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let trimmed = input.trim();
    let want_len = N * 2;
    if trimmed.len() != want_len {
        return Err(format!(
            "expected {want_len} hex characters, got {}",
            trimmed.len()
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("value must be hex-encoded".to_string());
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let byte =
            u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16).map_err(|err| err.to_string())?;
        out[i] = byte;
    }
    Ok(out)
}

impl TunConfig {
    fn from_token_string(token_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = token_str.split(':').collect();
        if parts.len() != 2 {
            return Err("token format: key_id:secret (both hex-encoded)".to_string());
        }

        let key_id = parse_hex_exact::<8>(parts[0])?;
        let secret = parse_hex_exact::<32>(parts[1])?;

        Ok(Self { key_id, secret })
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn xdg_config_home() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(v));
    }
    home_dir().map(|h| h.join(".config"))
}

fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    Ok(())
}

fn copy_self_to(target: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    ensure_parent_dir(target)?;
    std::fs::copy(&exe, target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn service_filename(service_name: &str) -> String {
    if service_name.ends_with(".service") {
        service_name.to_string()
    } else {
        format!("{service_name}.service")
    }
}

fn systemctl(scope_user: bool, args: &[&str]) -> anyhow::Result<()> {
    let mut cmd = ProcessCommand::new("systemctl");
    if scope_user {
        cmd.arg("--user");
    }
    cmd.args(args);
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("systemctl failed: {status}");
    }
    Ok(())
}

fn write_secret_env_file(path: &Path, token: &str, rust_log: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    writeln!(f, "LURE_TUN_TOKEN={token}")?;
    writeln!(f, "RUST_LOG={rust_log}")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn render_unit(exe: &Path, endpoint: &str, env_file: &Path, scope_user: bool) -> String {
    // Keep secrets out of ExecStart args; use EnvironmentFile instead.
    let wanted_by = if scope_user {
        "default.target"
    } else {
        "multi-user.target"
    };
    format!(
        r#"[Unit]
Description=Tunure tunnel agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={}
ExecStart={} agent {}
Restart=always
RestartSec=2

[Install]
WantedBy={}
"#,
        env_file.display(),
        exe.display(),
        endpoint,
        wanted_by
    )
}

fn resolve_endpoint(endpoint: &str) -> anyhow::Result<SocketAddr> {
    // Fast-path: allow raw SocketAddr (IP:port) without any resolver calls.
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Accept host:port and resolve via the system resolver.
    // Note: this is a blocking call; acceptable for a CLI agent since it only runs on connect/reconnect.
    let mut addrs = endpoint.to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses found for endpoint: {endpoint}"))
}

fn run_systemd_install(args: SystemdInstallArgs) -> anyhow::Result<()> {
    let scope_user = if args.system {
        false
    } else if args.user {
        true
    } else {
        // Default to --user; it does not require root.
        true
    };

    if args.user && args.system {
        anyhow::bail!("choose one: --user or --system");
    }

    let token_str = args.token.ok_or_else(|| {
        anyhow::anyhow!("token is required (use --token or LURE_TUN_TOKEN env var)")
    })?;
    let cfg = TunConfig::from_token_string(&token_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let key_id_hex = hex::encode(cfg.key_id);
    let service_base = args
        .name
        .unwrap_or_else(|| format!("tunure-agent-{key_id_hex}"));
    let service_file = service_filename(&service_base);

    let exe = std::env::current_exe()?;

    let (unit_dir, env_dir) = if scope_user {
        let cfg_home = xdg_config_home()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir (HOME required)"))?;
        (
            cfg_home.join("systemd").join("user"),
            cfg_home.join("tunure"),
        )
    } else {
        (
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from("/etc/tunure"),
        )
    };

    let default_bin_path = if scope_user {
        home_dir()
            .ok_or_else(|| anyhow::anyhow!("HOME is required for --user install"))?
            .join(".local")
            .join("bin")
            .join("tunure")
    } else {
        PathBuf::from("/usr/local/bin/tunure")
    };
    let installed_bin = args
        .bin_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or(default_bin_path);
    if args.install_bin {
        if let Err(err) = copy_self_to(&installed_bin) {
            error!(
                "failed to install tunure binary to {}: {err}; using current exe instead",
                installed_bin.display()
            );
        }
    }
    let exec_bin = if args.install_bin && installed_bin.exists() {
        installed_bin.clone()
    } else {
        exe.clone()
    };

    ensure_dir(&unit_dir)?;
    ensure_dir(&env_dir)?;

    let env_file = env_dir.join(format!("{service_base}.env"));
    write_secret_env_file(&env_file, &token_str, &args.rust_log)?;

    let unit_path = unit_dir.join(&service_file);
    std::fs::write(
        &unit_path,
        render_unit(&exec_bin, &args.endpoint, &env_file, scope_user),
    )?;

    info!("wrote unit: {}", unit_path.display());
    info!("wrote env:  {}", env_file.display());
    if args.install_bin {
        info!("service exe: {}", exec_bin.display());
    }

    if args.enable_now {
        if let Err(err) = systemctl(scope_user, &["daemon-reload"]) {
            error!("systemctl daemon-reload failed: {err}");
        }
        if let Err(err) = systemctl(scope_user, &["enable", "--now", &service_file]) {
            error!("systemctl enable --now failed: {err}");
            eprintln!("unit written, but systemctl failed; try manually:");
            if scope_user {
                eprintln!("  systemctl --user daemon-reload");
                eprintln!("  systemctl --user enable --now {service_file}");
            } else {
                eprintln!("  systemctl daemon-reload");
                eprintln!("  systemctl enable --now {service_file}");
            }
        }
    } else {
        eprintln!("unit written; enable it with:");
        if scope_user {
            eprintln!("  systemctl --user daemon-reload");
            eprintln!("  systemctl --user enable --now {service_file}");
        } else {
            eprintln!("  systemctl daemon-reload");
            eprintln!("  systemctl enable --now {service_file}");
        }
    }

    Ok(())
}

fn run_systemd_uninstall(args: SystemdUninstallArgs) -> anyhow::Result<()> {
    let scope_user = if args.system {
        false
    } else if args.user {
        true
    } else {
        true
    };

    if args.user && args.system {
        anyhow::bail!("choose one: --user or --system");
    }

    let service_file = service_filename(&args.name);
    let cfg_home = if scope_user {
        Some(
            xdg_config_home()
                .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir (HOME required)"))?,
        )
    } else {
        None
    };
    let unit_path = if scope_user {
        cfg_home
            .as_ref()
            .expect("cfg_home must exist for scope_user")
            .join("systemd")
            .join("user")
            .join(&service_file)
    } else {
        PathBuf::from("/etc/systemd/system").join(&service_file)
    };
    let env_path = if scope_user {
        cfg_home
            .as_ref()
            .expect("cfg_home must exist for scope_user")
            .join("tunure")
            .join(format!("{}.env", args.name))
    } else {
        PathBuf::from("/etc/tunure").join(format!("{}.env", args.name))
    };

    // Best-effort stop/disable.
    let _ = systemctl(scope_user, &["disable", "--now", &service_file]);
    let _ = systemctl(scope_user, &["daemon-reload"]);

    if unit_path.exists() {
        std::fs::remove_file(&unit_path)?;
        info!("removed unit: {}", unit_path.display());
    } else {
        info!("unit not found: {}", unit_path.display());
    }

    if env_path.exists() {
        let _ = std::fs::remove_file(&env_path);
    }

    Ok(())
}

async fn read_server_msg(
    conn: &mut net::sock::Connection,
    buf: &mut Vec<u8>,
    read_buf: &mut Vec<u8>,
) -> anyhow::Result<ServerMsg> {
    loop {
        if let Some((msg, consumed)) = tun::decode_server_msg(buf)? {
            buf.drain(..consumed);
            return Ok(msg);
        }
        let (n, next) = conn.read_chunk(std::mem::take(read_buf)).await?;
        *read_buf = next;
        if n == 0 {
            anyhow::bail!("server closed connection");
        }
        buf.extend_from_slice(&read_buf[..n]);
    }
}

async fn send_agent_hello(
    conn: &mut net::sock::Connection,
    hello: AgentHello,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    tun::encode_agent_hello(&hello, &mut buf)?;
    conn.write_all(buf).await?;
    Ok(())
}

async fn handle_session(
    ingress: SocketAddr,
    config: TunConfig,
    session: [u8; 32],
) -> anyhow::Result<()> {
    let mut agent_conn = tun::connect_agent(ingress).await?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let hmac = tun::compute_agent_hmac(
        &config.secret,
        &config.key_id,
        timestamp,
        Intent::Connect,
        Some(&session),
    );

    send_agent_hello(
        &mut agent_conn,
        AgentHello {
            version: tun::VERSION,
            intent: Intent::Connect,
            key_id: config.key_id,
            timestamp,
            hmac,
            session: Some(session),
        },
    )
    .await?;

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    let target = loop {
        match read_server_msg(&mut agent_conn, &mut buf, &mut read_buf).await? {
            ServerMsg::TargetAddr(addr) => break addr,
            _ => continue,
        }
    };

    let mut target_conn = net::sock::Connection::connect(target).await?;
    // If the server already sent some tunneled bytes after TargetAddr in the same read,
    // forward them to the backend before entering passthrough mode.
    if !buf.is_empty() {
        target_conn.write_all(std::mem::take(&mut buf)).await?;
    }
    net::sock::passthrough_basic(&mut agent_conn, &mut target_conn).await?;
    Ok(())
}

async fn listen_once(ingress: SocketAddr, config: TunConfig) -> anyhow::Result<()> {
    let mut listener = tun::connect_agent(ingress).await?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let hmac = tun::compute_agent_hmac(
        &config.secret,
        &config.key_id,
        timestamp,
        Intent::Listen,
        None,
    );

    send_agent_hello(
        &mut listener,
        AgentHello {
            version: tun::VERSION,
            intent: Intent::Listen,
            key_id: config.key_id,
            timestamp,
            hmac,
            session: None,
        },
    )
    .await?;

    info!(
        "registered with proxy: key_id={}",
        hex::encode(config.key_id)
    );

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    loop {
        let msg = read_server_msg(&mut listener, &mut buf, &mut read_buf).await?;
        if let ServerMsg::SessionOffer(session) = msg {
            let ingress = ingress;
            let config = TunConfig {
                key_id: config.key_id,
                secret: config.secret,
            };
            match net::sock::backend_kind() {
                net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
                    tokio::task::spawn_local(async move {
                        if let Err(e) = handle_session(ingress, config, session).await {
                            error!("tun handle_session failed: {e}");
                        }
                    });
                }
                net::sock::BackendKind::Uring => {
                    net::sock::uring::spawn(async move {
                        if let Err(e) = handle_session(ingress, config, session).await {
                            error!("tun handle_session failed: {e}");
                        }
                    });
                }
            }
        }
    }
}

async fn run(ingress: SocketAddr, config: TunConfig) -> anyhow::Result<()> {
    let mut delay = std::time::Duration::from_millis(250);
    let max_delay = std::time::Duration::from_secs(10);

    loop {
        match listen_once(
            ingress,
            TunConfig {
                key_id: config.key_id,
                secret: config.secret,
            },
        )
        .await
        {
            Ok(()) => {
                // listen_once currently never returns Ok, but keep this behavior robust.
                delay = std::time::Duration::from_millis(250);
            }
            Err(e) => {
                error!("listener disconnected: {e}; reconnecting in {delay:?}");
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(max_delay, delay.saturating_mul(2));
            }
        }
    }
}

fn run_sign(args: SignArgs) -> anyhow::Result<()> {
    let intent = match args.intent.as_str() {
        "listen" => Intent::Listen,
        "connect" => Intent::Connect,
        other => anyhow::bail!("invalid intent {other}"),
    };

    let cfg = TunConfig::from_token_string(&args.token).map_err(|e| anyhow::anyhow!("{e}"))?;

    let timestamp = args.timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs()
    });

    let session = match intent {
        Intent::Listen => None,
        Intent::Connect => {
            let s = args
                .session
                .ok_or_else(|| anyhow::anyhow!("--session is required for connect intent"))?;
            Some(parse_hex_exact::<32>(&s).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
    };

    let hmac = tun::compute_agent_hmac(
        &cfg.secret,
        &cfg.key_id,
        timestamp,
        intent,
        session.as_ref(),
    );

    println!("version={}", tun::VERSION);
    println!("intent={}", args.intent);
    println!("key_id={}", hex::encode(cfg.key_id));
    println!("timestamp={timestamp}");
    if let Some(s) = session {
        println!("session={}", hex::encode(s));
    }
    println!("hmac={}", hex::encode(hmac));

    Ok(())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    match cli.command {
        Command::Systemd(args) => {
            let result = match args.command {
                SystemdCommand::Install(install) => run_systemd_install(install),
                SystemdCommand::Uninstall(uninstall) => run_systemd_uninstall(uninstall),
            };
            if let Err(err) = result {
                error!("{err}");
                std::process::exit(1);
            }
        }
        Command::Sign(args) => {
            if let Err(err) = run_sign(args) {
                error!("{err}");
                std::process::exit(1);
            }
        }
        Command::Agent(args) => {
            let token_str = if let Some(token) = args.token {
                token
            } else {
                eprintln!("error: token is required (use --token or LURE_TUN_TOKEN env var)");
                eprintln!(
                    "token format: key_id:secret (both 16-char and 64-char hex respectively)"
                );
                std::process::exit(1);
            };

            let proxy: SocketAddr = match resolve_endpoint(&args.proxy) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("error: invalid proxy endpoint {}: {err}", args.proxy);
                    eprintln!("expected: <ip:port> or <host:port>");
                    std::process::exit(1);
                }
            };

            let config = match TunConfig::from_token_string(&token_str) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("error: invalid token: {err}");
                    std::process::exit(1);
                }
            };

            match net::sock::backend_kind() {
                net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .expect("failed to build tokio runtime");
                    let local = tokio::task::LocalSet::new();
                    if let Err(err) = rt.block_on(local.run_until(run(proxy, config))) {
                        eprintln!("tunnel agent failed: {err}");
                        std::process::exit(1);
                    }
                }
                net::sock::BackendKind::Uring => {
                    let result = net::sock::uring::start(async move { run(proxy, config).await });
                    if let Err(err) = result {
                        eprintln!("tunnel agent failed: {err}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
