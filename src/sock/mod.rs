pub(crate) mod tokio;
pub(crate) mod uring;

pub use net::sock::{BackendKind, BackendSelection, Connection, Listener, backend_kind, backend_selection};

pub async fn passthrough_now<'a, 'b>(
    client: &mut crate::connection::EncodedConnection<'a>,
    server: &mut crate::connection::EncodedConnection<'b>,
    session: &crate::router::Session,
) -> anyhow::Result<()> {
    let client = client.as_inner_mut();
    let server = server.as_inner_mut();
    match (client, server) {
        (Connection::Tokio(client), Connection::Tokio(server)) => {
            tokio::passthrough_now(client, server, session).await
        }
        (Connection::Uring(client), Connection::Uring(server)) => {
            uring::passthrough_now(client, server, session).await
        }
        _ => Err(anyhow::anyhow!(
            "mismatched connection backends for passthrough"
        )),
    }
}
