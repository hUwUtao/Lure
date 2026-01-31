use std::net::SocketAddr;

use tun::{AgentHello, Intent, ServerMsg};

fn parse_token(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|err| err.to_string())?;
            out[i] = byte;
        }
        return Ok(out);
    }
    let decoded = base64::decode(trimmed).map_err(|err| err.to_string())?;
    if decoded.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

async fn read_server_msg(
    conn: &mut net::sock::Connection,
    buf: &mut Vec<u8>,
) -> anyhow::Result<ServerMsg> {
    loop {
        if let Some((msg, consumed)) = tun::decode_server_msg(buf)? {
            buf.drain(..consumed);
            return Ok(msg);
        }
        let (n, next) = conn.read_chunk(std::mem::take(buf)).await?;
        *buf = next;
        if n == 0 {
            anyhow::bail!("server closed connection");
        }
    }
}

async fn send_agent_hello(
    conn: &mut net::sock::Connection,
    hello: AgentHello,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    tun::encode_agent_hello(&hello, &mut buf);
    conn.write_all(buf).await?;
    Ok(())
}

async fn handle_session(
    ingress: SocketAddr,
    token: [u8; 32],
    session: [u8; 32],
) -> anyhow::Result<()> {
    let mut agent_conn = tun::connect_agent(ingress).await?;
    send_agent_hello(
        &mut agent_conn,
        AgentHello {
            version: tun::VERSION,
            intent: Intent::Connect,
            token,
            session: Some(session),
        },
    )
    .await?;

    let mut buf = Vec::new();
    let target = loop {
        match read_server_msg(&mut agent_conn, &mut buf).await? {
            ServerMsg::TargetAddr(addr) => break addr,
            _ => continue,
        }
    };

    let mut target_conn = net::sock::Connection::connect(target).await?;
    net::sock::passthrough_basic(&mut agent_conn, &mut target_conn).await?;
    Ok(())
}

async fn run(ingress: SocketAddr, token: [u8; 32]) -> anyhow::Result<()> {
    let mut listener = tun::connect_agent(ingress).await?;
    send_agent_hello(
        &mut listener,
        AgentHello {
            version: tun::VERSION,
            intent: Intent::Listen,
            token,
            session: None,
        },
    )
    .await?;

    let mut buf = Vec::new();
    loop {
        let msg = read_server_msg(&mut listener, &mut buf).await?;
        if let ServerMsg::SessionOffer(session) = msg {
            let ingress = ingress;
            let token = token;
            match net::sock::backend_kind() {
                net::sock::BackendKind::Tokio => {
                    tokio::spawn(async move {
                        let _ = handle_session(ingress, token, session).await;
                    });
                }
                net::sock::BackendKind::Uring => {
                    net::sock::uring::spawn(async move {
                        let _ = handle_session(ingress, token, session).await;
                    });
                }
            }
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let ingress = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:25565".to_string());
    let token = args.next().unwrap_or_default();

    if token.is_empty() {
        eprintln!("usage: tun <ingress_addr> <token>");
        std::process::exit(1);
    }

    let ingress: SocketAddr = match ingress.parse() {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("invalid ingress addr: {err}");
            std::process::exit(1);
        }
    };

    let token = match parse_token(&token) {
        Ok(token) => token,
        Err(err) => {
            eprintln!("invalid token: {err}");
            std::process::exit(1);
        }
    };

    match net::sock::backend_kind() {
        net::sock::BackendKind::Tokio => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            if let Err(err) = rt.block_on(run(ingress, token)) {
                eprintln!("tunnel agent failed: {err}");
                std::process::exit(1);
            }
        }
        net::sock::BackendKind::Uring => {
            let result = net::sock::uring::start(async move { run(ingress, token).await });
            if let Err(err) = result {
                eprintln!("tunnel agent failed: {err}");
                std::process::exit(1);
            }
        }
    }
}
