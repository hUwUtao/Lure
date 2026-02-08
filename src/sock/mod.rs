#[cfg(target_os = "linux")]
pub(crate) mod epoll;
#[cfg(not(target_os = "linux"))]
pub(crate) mod epoll {
    use crate::router::Session;

    pub(crate) async fn passthrough_now(
        _client: &mut net::sock::epoll::Connection,
        _server: &mut net::sock::epoll::Connection,
        _session: &Session,
    ) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("epoll backend is only supported on linux"))
    }
}
pub(crate) mod tokio;
#[cfg(feature = "uring")]
pub(crate) mod uring;

pub use net::sock::{
    BackendKind, BackendSelection, LureConnection, LureListener, backend_kind, backend_selection,
};

pub(crate) async fn passthrough_now<'a, 'b>(
    client: &mut crate::connection::EncodedConnection<'a>,
    server: &mut crate::connection::EncodedConnection<'b>,
    session: &crate::router::Session,
) -> anyhow::Result<()> {
    let client = client.as_inner_mut();
    let server = server.as_inner_mut();
    let Some(client) = client.as_connection_mut() else {
        return Err(anyhow::anyhow!(
            "passthrough requires a concrete connection backend"
        ));
    };
    let Some(server) = server.as_connection_mut() else {
        return Err(anyhow::anyhow!(
            "passthrough requires a concrete connection backend"
        ));
    };

    match (client, server) {
        (net::sock::Connection::Tokio(client), net::sock::Connection::Tokio(server)) => {
            tokio::passthrough_now(client, server, session).await
        }
        (net::sock::Connection::Epoll(client), net::sock::Connection::Epoll(server)) => {
            epoll::passthrough_now(client, server, session).await
        }
        #[cfg(feature = "uring")]
        (net::sock::Connection::Uring(client), net::sock::Connection::Uring(server)) => {
            uring::passthrough_now(client, server, session).await
        }
        #[cfg(not(feature = "uring"))]
        (net::sock::Connection::Uring(_), net::sock::Connection::Uring(_)) => Err(anyhow::anyhow!(
            "io_uring backend is disabled at compile time (build with `--features uring`)"
        )),
        _ => Err(anyhow::anyhow!(
            "mismatched connection backends for passthrough"
        )),
    }
}
