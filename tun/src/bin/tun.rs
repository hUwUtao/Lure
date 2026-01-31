use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:25565".to_string());
    let addr: SocketAddr = match addr.parse() {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("invalid address: {err}");
            std::process::exit(1);
        }
    };

    match tun::connect_agent(addr).await {
        Ok(mut conn) => {
            let _ = conn.shutdown().await;
            eprintln!("tun agent stub connected to {addr}");
        }
        Err(err) => {
            eprintln!("failed to connect to {addr}: {err}");
            std::process::exit(1);
        }
    }
}
