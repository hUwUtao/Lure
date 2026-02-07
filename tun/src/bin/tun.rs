use std::net::SocketAddr;

use clap::{Args, Parser, Subcommand};
use log::{error, info};
use tun::{AgentHello, Intent, ServerMsg};

#[derive(Parser)]
#[command(name = "tun")]
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
}

#[derive(Args)]
struct AgentArgs {
    /// Proxy address (host:port)
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

async fn run(ingress: SocketAddr, config: TunConfig) -> anyhow::Result<()> {
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
                        let _ = handle_session(ingress, config, session).await;
                    });
                }
                net::sock::BackendKind::Uring => {
                    net::sock::uring::spawn(async move {
                        let _ = handle_session(ingress, config, session).await;
                    });
                }
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

            let proxy: SocketAddr = match args.proxy.parse() {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("error: invalid proxy address: {err}");
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
