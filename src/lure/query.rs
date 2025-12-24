use serde_json::json;

use crate::{config::LureConfig, connection::EncodedConnection};

pub(crate) fn placeholder_status_response(brand: &str, message: &str) -> String {
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

pub(crate) fn placeholder_status_json(config: &LureConfig, label: &str) -> String {
    let brand = config.string_value("SERVER_LIST_BRAND");
    let target_label = config.string_value(label);
    placeholder_status_response(brand.as_ref(), target_label.as_ref())
}

pub(crate) async fn send_status_failure(
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
