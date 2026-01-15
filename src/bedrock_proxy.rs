use std::net::SocketAddr;

use anyhow::Context;
use bytes::Bytes;
use tokio_raknet::protocol::reliability::Reliability;
use tokio_raknet::transport::{Message, RaknetListener, RaknetStream};

use crate::router::{ResolvedRoute, RouterInstance};
use net::bedrock::{
    COMPRESSION_ALGORITHM_NONE,
    COMPRESSION_ALGORITHM_SNAPPY,
    COMPRESSION_ALGORITHM_ZLIB,
    Compression,
    NetworkSettings,
    decode_login_packet,
    decode_network_settings,
    decode_packet_batch,
    encode_network_settings,
    encode_packet_batch,
};
use net::bedrock::varint::read_uvarint;
use net::bedrock::{NETWORK_SETTINGS_PACKET_ID, REQUEST_NETWORK_SETTINGS_PACKET_ID};

const MAX_BUFFERED_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
struct BufferedMessage {
    buffer: Bytes,
    reliability: Reliability,
    channel: u8,
}

pub async fn start(bind: SocketAddr, router: &'static RouterInstance) -> anyhow::Result<()> {
    let mut listener = RaknetListener::bind(bind).await?;
    log::info!("bedrock proxy listening on {bind}");

    while let Some(stream) = listener.accept().await {
        tokio::spawn(handle_connection(stream, router));
    }

    Ok(())
}

async fn handle_connection(
    mut client: RaknetStream,
    router: &'static RouterInstance,
) -> anyhow::Result<()> {
    let client_addr = client.peer_addr();
    let mut buffered: Vec<BufferedMessage> = Vec::new();
    let mut buffered_bytes = 0usize;
    let mut client_compression = Compression::None;
    let mut backend_compression: Option<Compression> = None;
    let mut sent_network_settings = false;
    let mut resolved: Option<ResolvedRoute> = None;

    while resolved.is_none() {
        let Some(msg) = recv_msg(&mut client).await else {
            return Ok(());
        };

        buffered_bytes = buffered_bytes.saturating_add(msg.buffer.len());
        if buffered_bytes > MAX_BUFFERED_BYTES {
            log::warn!("bedrock client {client_addr} exceeded buffer limit");
            return Ok(());
        }

        if let Some(server_address) = try_extract_server_address(
            &msg.buffer,
            &mut client_compression,
            &mut sent_network_settings,
            &client,
        )
        .await?
        {
            let hostname = host_from_server_address(&server_address);
            resolved = router.resolve(&hostname).await;
            if resolved.is_none() {
                log::warn!(
                    "bedrock client {client_addr} no route for server address {server_address}"
                );
                return Ok(());
            }
        }

        buffered.push(msg);
    }

    let resolved = resolved.expect("resolved route");
    let backend = resolved.endpoint;
    let mut server = RaknetStream::connect(backend)
        .await
        .with_context(|| format!("connect bedrock backend {backend}"))?;
    let mut filter_backend_settings = sent_network_settings;
    let mut translate_client_to_backend = true;
    let mut translate_backend_to_client = true;
    let mut pending_to_backend: Vec<BufferedMessage> = Vec::new();
    let mut pending_bytes = 0usize;

    if sent_network_settings {
        for msg in buffered.drain(..) {
            if batch_contains_request_settings(&msg.buffer) {
                send_msg(&server, msg).await?;
            } else {
                pending_bytes = pending_bytes.saturating_add(msg.buffer.len());
                pending_to_backend.push(msg);
            }
        }
    } else {
        for msg in buffered.drain(..) {
            send_msg(&server, msg).await?;
        }
    }

    loop {
        tokio::select! {
            msg = recv_msg(&mut client) => {
                let Some(msg) = msg else {
                    break;
                };
                if sent_network_settings
                    && backend_compression.is_none()
                    && !batch_contains_request_settings(&msg.buffer)
                {
                    pending_bytes = pending_bytes.saturating_add(msg.buffer.len());
                    if pending_bytes > MAX_BUFFERED_BYTES {
                        log::warn!("bedrock client {client_addr} exceeded pending buffer limit");
                        return Ok(());
                    }
                    pending_to_backend.push(msg);
                    continue;
                }
                let msg = match backend_compression {
                    Some(backend_compression) => translate_message(
                        msg,
                        &mut client_compression,
                        backend_compression,
                        &mut translate_client_to_backend,
                    )?,
                    None => msg,
                };
                send_msg(&server, msg).await?;
            }
            msg = recv_msg(&mut server) => {
                let Some(msg) = msg else {
                    break;
                };
                let msg = handle_backend_message(
                    msg,
                    client_compression,
                    &mut backend_compression,
                    &mut filter_backend_settings,
                    &mut translate_backend_to_client,
                )?;
                if let Some(msg) = msg {
                    send_msg(&client, msg).await?;
                }
                if let Some(backend_compression) = backend_compression {
                    if !pending_to_backend.is_empty() {
                        flush_pending(
                            &server,
                            &mut pending_to_backend,
                            &mut pending_bytes,
                            &mut client_compression,
                            backend_compression,
                            &mut translate_client_to_backend,
                        )
                        .await?;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn recv_msg(stream: &mut RaknetStream) -> Option<BufferedMessage> {
    let msg = match stream.recv_msg().await? {
        Ok(msg) => msg,
        Err(err) => {
            log::debug!("raknet recv error: {err:?}");
            return None;
        }
    };

    Some(BufferedMessage {
        buffer: msg.buffer,
        reliability: msg.reliability,
        channel: msg.channel,
    })
}

async fn send_msg(stream: &RaknetStream, msg: BufferedMessage) -> anyhow::Result<()> {
    let message = Message::new(msg.buffer)
        .reliability(msg.reliability)
        .channel(msg.channel);
    stream.send(message).await.context("raknet send failed")
}

async fn flush_pending(
    server: &RaknetStream,
    pending: &mut Vec<BufferedMessage>,
    pending_bytes: &mut usize,
    client_compression: &mut Compression,
    backend_compression: Compression,
    translate_client_to_backend: &mut bool,
) -> anyhow::Result<()> {
    for msg in pending.drain(..) {
        let msg = translate_message(
            msg,
            client_compression,
            backend_compression,
            translate_client_to_backend,
        )?;
        send_msg(server, msg).await?;
    }
    *pending_bytes = 0;
    Ok(())
}

async fn try_extract_server_address(
    buffer: &Bytes,
    compression: &mut Compression,
    sent_network_settings: &mut bool,
    client: &RaknetStream,
) -> anyhow::Result<Option<String>> {
    let Some(packets) = decode_batch_with_state(buffer, compression) else {
        return Ok(None);
    };

    for packet in packets {
        if !*sent_network_settings && is_request_network_settings(&packet) {
            send_network_settings(client).await?;
            *compression = Compression::Zlib;
            *sent_network_settings = true;
        }
        if let Ok(login) = decode_login_packet(&packet) {
            if let Ok(Some(server_address)) = login.server_address() {
                return Ok(Some(server_address));
            }
        }
    }

    Ok(None)
}

async fn send_network_settings(client: &RaknetStream) -> anyhow::Result<()> {
    let settings = NetworkSettings {
        compression_threshold: 1,
        compression_algorithm: COMPRESSION_ALGORITHM_ZLIB,
        enable_client_throttling: false,
        client_throttle_threshold: 0,
        client_throttle_scalar: 0.0,
    };
    let packet = encode_network_settings(&settings);
    let batch = encode_packet_batch(&[packet], Compression::None)?;
    let message = Message::new(batch).reliability(Reliability::ReliableOrdered);
    client.send(message).await.context("send network settings")
}

fn is_request_network_settings(packet: &[u8]) -> bool {
    let mut input = packet;
    matches!(read_uvarint(&mut input), Ok(REQUEST_NETWORK_SETTINGS_PACKET_ID))
}

fn batch_contains_request_settings(buffer: &[u8]) -> bool {
    let Some((_, packets)) = decode_batch_with_fallback(buffer, Compression::None) else {
        return false;
    };
    packets.iter().any(|packet| is_request_network_settings(packet))
}

fn packet_has_id(packet: &[u8], id: u32) -> bool {
    let mut input = packet;
    matches!(read_uvarint(&mut input), Ok(value) if value == id)
}

fn handle_backend_message(
    msg: BufferedMessage,
    client_compression: Compression,
    backend_compression: &mut Option<Compression>,
    filter_backend_settings: &mut bool,
    translate_backend_to_client: &mut bool,
) -> anyhow::Result<Option<BufferedMessage>> {
    let need_decode = *filter_backend_settings
        || backend_compression.is_none()
        || (*translate_backend_to_client
            && backend_compression.map_or(false, |compression| compression != client_compression));

    if !need_decode {
        return Ok(Some(msg));
    }

    let Some((detected_compression, packets)) =
        decode_batch_with_optional_state(&msg.buffer, backend_compression)
    else {
        *filter_backend_settings = false;
        *translate_backend_to_client = false;
        return Ok(Some(msg));
    };

    let mut filtered = Vec::new();
    let mut found_settings = false;
    for packet in packets {
        if packet_has_id(&packet, NETWORK_SETTINGS_PACKET_ID) {
            found_settings = true;
            if let Ok(settings) = decode_network_settings(&packet) {
                if let Some(compression) =
                    compression_from_algorithm(settings.compression_algorithm)
                {
                    *backend_compression = Some(compression);
                } else {
                    log::warn!(
                        "bedrock backend uses unknown compression algorithm {}",
                        settings.compression_algorithm
                    );
                }
            }
            continue;
        }
        filtered.push(packet);
    }

    if found_settings {
        *filter_backend_settings = false;
    }

    if filtered.is_empty() {
        return Ok(None);
    }

    if !found_settings
        && (!*translate_backend_to_client || detected_compression == client_compression)
    {
        return Ok(Some(msg));
    }

    let batch = encode_packet_batch(&filtered, client_compression)?;
    Ok(Some(BufferedMessage {
        buffer: Bytes::from(batch),
        reliability: msg.reliability,
        channel: msg.channel,
    }))
}

fn translate_message(
    msg: BufferedMessage,
    src_compression: &mut Compression,
    dst_compression: Compression,
    translate: &mut bool,
) -> anyhow::Result<BufferedMessage> {
    if !*translate || *src_compression == dst_compression {
        return Ok(msg);
    }

    let Some(packets) = decode_batch_with_state(&msg.buffer, src_compression) else {
        *translate = false;
        return Ok(msg);
    };

    let batch = encode_packet_batch(&packets, dst_compression)?;
    Ok(BufferedMessage {
        buffer: Bytes::from(batch),
        reliability: msg.reliability,
        channel: msg.channel,
    })
}

fn decode_batch_with_state(
    buffer: &[u8],
    compression: &mut Compression,
) -> Option<Vec<Vec<u8>>> {
    let (detected, packets) = decode_batch_with_fallback(buffer, *compression)?;
    *compression = detected;
    Some(packets)
}

fn decode_batch_with_optional_state(
    buffer: &[u8],
    compression: &mut Option<Compression>,
) -> Option<(Compression, Vec<Vec<u8>>)> {
    let preferred = compression.unwrap_or(Compression::None);
    let (detected, packets) = decode_batch_with_fallback(buffer, preferred)?;
    if compression.map_or(true, |current| current != detected) {
        *compression = Some(detected);
    }
    Some((detected, packets))
}

fn decode_batch_with_fallback(
    buffer: &[u8],
    preferred: Compression,
) -> Option<(Compression, Vec<Vec<u8>>)> {
    if let Ok(packets) = decode_packet_batch(buffer, preferred) {
        return Some((preferred, packets));
    }

    for compression in [Compression::None, Compression::Zlib, Compression::Snappy] {
        if compression == preferred {
            continue;
        }
        if let Ok(packets) = decode_packet_batch(buffer, compression) {
            return Some((compression, packets));
        }
    }

    None
}

fn compression_from_algorithm(algorithm: u16) -> Option<Compression> {
    match algorithm {
        COMPRESSION_ALGORITHM_ZLIB => Some(Compression::Zlib),
        COMPRESSION_ALGORITHM_SNAPPY => Some(Compression::Snappy),
        COMPRESSION_ALGORITHM_NONE => Some(Compression::None),
        _ => None,
    }
}

fn host_from_server_address(address: &str) -> String {
    let trimmed = address.trim().trim_matches('\0');
    if let Some(start) = trimmed.find('[') {
        if let Some(end) = trimmed[start + 1..].find(']') {
            let host = &trimmed[start + 1..start + 1 + end];
            return host.to_string();
        }
    }

    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            return host.to_string();
        }
    }

    trimmed.to_string()
}
