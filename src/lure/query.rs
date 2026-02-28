use net::{StatusPingC2s, StatusPongS2c};
use serde_json::json;

use crate::{
    config::LureConfig,
    connection::EncodedConnection,
    threat::{ClientFail, ClientIntent, IntentTag, ThreatControlService},
};

pub fn placeholder_status_response(brand: &str, message: &str) -> String {
    json!({
        "version": {
            "name": brand,
            "protocol": -1
        },
        "description": {
            "text": message
        }
    })
    .to_string()
}

pub fn placeholder_status_json(config: &LureConfig, label: &str) -> String {
    let brand = config.string_value("SERVER_LIST_BRAND");
    let target_label = config.string_value(label);
    placeholder_status_response(brand.as_ref(), target_label.as_ref())
}

pub async fn send_status_failure(
    client: &mut EncodedConnection<'_>,
    config: &LureConfig,
    label: &str,
) -> anyhow::Result<()> {
    let placeholder = placeholder_status_json(config, label);
    client
        .send(&net::StatusResponseS2c { json: &placeholder })
        .await?;
    Ok(())
}

/// Send a cached or computed status response from raw JSON bytes
pub async fn send_status_response(
    client: &mut EncodedConnection<'_>,
    json_bytes: &[u8],
) -> anyhow::Result<()> {
    // Convert bytes to string for sending (StatusResponseS2c expects &str)
    let json_str = std::str::from_utf8(json_bytes)?;
    client.send(&net::StatusResponseS2c { json: json_str }).await?;
    Ok(())
}

/// Handle ping/pong locally by echoing the client's timestamp
pub async fn handle_ping_pong_local(
    client: &mut EncodedConnection<'_>,
    threat: &ThreatControlService,
) -> anyhow::Result<()> {
    let intent = ClientIntent {
        tag: IntentTag::Query,
        duration: std::time::Duration::from_secs(1),
    };

    let ping = match threat
        .nuisance(client.recv::<StatusPingC2s>(), intent)
        .await
    {
        Ok(Ok(packet)) => packet,
        Ok(Err(err)) => return Err(err.into()),
        Err(err) => {
            if err.downcast_ref::<ClientFail>().is_some() {
                return Err(err);
            }
            return Err(err);
        }
    };

    // Echo the ping payload back in the pong response
    client.send(&StatusPongS2c { payload: ping.payload }).await?;
    Ok(())
}
