use std::{borrow::Cow, net::SocketAddr, time::Duration};

use log::debug;
use tokio::{net::TcpStream, time::timeout};

use crate::{
    connection::{EncodedConnection, SocketIntent},
    logging::LureLogger,
    packet::{OwnedHandshake, encode_uncompressed_packet},
    config::LureConfig,
    utils::Connection,
};

mod headers;
use headers::create_proxy_protocol_header;
#[derive(Debug, thiserror::Error)]
pub(crate) enum BackendConnectError {
    #[error("backend connect failed")]
    Connect(#[source] anyhow::Error),
    #[error("backend handshake failed")]
    Handshake(#[source] anyhow::Error),
}

pub(crate) async fn connect(
    address: SocketAddr,
    handshake: &OwnedHandshake,
    endpoint_host: Option<&str>,
    endpoint_port: u16,
    preserve_host: bool,
    proxied: bool,
    config: &LureConfig,
    client_addr: SocketAddr,
) -> Result<Connection, BackendConnectError> {
    let mut backend = open_backend_connection(address)
        .await
        .map_err(BackendConnectError::Connect)?;

    {
        let mut server = EncodedConnection::new(&mut backend, SocketIntent::GreetToBackend);
        init_handshake(
            &mut server,
            handshake,
            endpoint_host,
            endpoint_port,
            preserve_host,
            proxied,
            config,
            client_addr,
        )
        .await
        .map_err(BackendConnectError::Handshake)?;
    }

    Ok(backend)
}

fn backend_handshake_parts<'a>(
    handshake: &'a OwnedHandshake,
    endpoint_host: Option<&str>,
    endpoint_port: u16,
    preserve_host: bool,
) -> (Cow<'a, str>, u16) {
    if !preserve_host {
        let mut new_server_address = String::new();
        if let Some(host) = endpoint_host {
            new_server_address.push_str(host);
        }
        if let Some(nul) = handshake.server_address.find('\0') {
            new_server_address.push_str(&handshake.server_address[nul..]);
        }
        return (Cow::Owned(new_server_address), endpoint_port);
    }

    (
        Cow::Borrowed(handshake.server_address.as_ref()),
        handshake.server_port,
    )
}

async fn init_handshake(
    server: &mut EncodedConnection<'_>,
    handshake: &OwnedHandshake,
    endpoint_host: Option<&str>,
    endpoint_port: u16,
    preserve_host: bool,
    proxied: bool,
    config: &LureConfig,
    client_addr: SocketAddr,
) -> anyhow::Result<()> {
    if proxied {
        let pkt = create_proxy_protocol_header(client_addr, config)?;
        server.send_raw(&pkt).await?;
        debug!("PP Sent");
    }

    let (server_address, server_port) =
        backend_handshake_parts(handshake, endpoint_host, endpoint_port, preserve_host);
    let packet = net::HandshakeC2s {
        protocol_version: handshake.protocol_version,
        server_address: server_address.as_ref(),
        server_port,
        next_state: handshake.next_state,
    };

    let encoded = encode_uncompressed_packet(&packet)?;
    server.send_raw(&encoded).await?;
    debug!("HS Sent");
    Ok(())
}

async fn open_backend_connection(address: SocketAddr) -> anyhow::Result<Connection> {
    let stream = timeout(Duration::from_secs(3), TcpStream::connect(address)).await??;
    debug!("Connected to backend: {}", address);

    if dotenvy::var("NO_NODELAY").is_err()
        && let Err(e) = stream.set_nodelay(true)
    {
        LureLogger::tcp_nodelay_failed(&e);
    }

    Ok(Connection::try_from(stream)?)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::packet::OwnedHandshake;

    fn handshake_with_addr(addr: &str) -> OwnedHandshake {
        OwnedHandshake {
            protocol_version: 0,
            server_address: Arc::from(addr),
            server_port: 25565,
            next_state: net::HandshakeNextState::Login,
        }
    }

    #[test]
    fn backend_handshake_preserves_suffix_after_first_nul() {
        let hs = handshake_with_addr("example.com\0FML2\0");
        let (address, _) = backend_handshake_parts(&hs, Some("backend.local"), 25565, false);
        assert_eq!(address.as_ref(), "backend.local\0FML2\0");

        let hs = handshake_with_addr("example.com\0FORGE\0");
        let (address, _) = backend_handshake_parts(&hs, Some("backend.local"), 25565, false);
        assert_eq!(address.as_ref(), "backend.local\0FORGE\0");
    }

    #[test]
    fn backend_handshake_keeps_raw_host_when_preserved() {
        let hs = handshake_with_addr("example.com\0FORGE\0");
        let (address, port) = backend_handshake_parts(&hs, Some("backend.local"), 25565, true);
        assert_eq!(address.as_ref(), hs.server_address.as_ref());
        assert_eq!(port, hs.server_port);
    }
}
