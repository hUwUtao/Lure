/// Integration tests for tunnel protocol and registry
/// Tests protocol encoding/decoding, registry state management, and concurrent safety
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn tunnel_basic_types() {
    // Test: Basic tunnel types are valid
    use lure::tunnel::{SessionToken, TunnelToken};

    let token = TunnelToken([0u8; 32]);
    let session = SessionToken([1u8; 32]);

    // Verify these can be cloned and compared
    let token2 = token;
    assert_eq!(token, token2);

    let session2 = session;
    assert_eq!(session, session2);
}


#[test]
fn tunnel_protocol_agent_hello_roundtrip() {
    // Test: Protocol encoding/decoding works end-to-end for AgentHello
    // Verifies wire format is correct

    use tun::{AgentHello, Intent, decode_agent_hello, encode_agent_hello};

    // Test Connect intent
    let hello = AgentHello {
        version: tun::VERSION,
        intent: Intent::Connect,
        token: [20u8; 32],
        session: Some([21u8; 32]),
    };

    let mut buf = Vec::new();
    encode_agent_hello(&hello, &mut buf).expect("encode should work");

    // Verify buffer structure
    assert_eq!(&buf[..4], &tun::MAGIC, "Magic bytes should match");
    assert_eq!(buf[4], tun::VERSION, "Version should match");
    assert_eq!(buf[5], Intent::Connect as u8, "Intent should be Connect");

    // Decode
    let (decoded, consumed) = decode_agent_hello(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded.version, hello.version);
    assert_eq!(decoded.intent, hello.intent);
    assert_eq!(decoded.token, hello.token);
    assert_eq!(decoded.session, hello.session);
    assert_eq!(consumed, 70, "Connect message should be 70 bytes");

    // Test Listen intent
    let hello_listen = AgentHello {
        version: tun::VERSION,
        intent: Intent::Listen,
        token: [22u8; 32],
        session: None,
    };

    let mut buf2 = Vec::new();
    encode_agent_hello(&hello_listen, &mut buf2).expect("encode should work");
    assert_eq!(buf2.len(), 38, "Listen message should be 38 bytes");

    let (decoded2, consumed2) = decode_agent_hello(&buf2)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded2.intent, Intent::Listen);
    assert_eq!(consumed2, 38);
}

#[test]
fn tunnel_ipv4_target_addr_roundtrip() {
    // Test: IPv4 target address encoding/decoding
    use tun::{ServerMsg, decode_server_msg, encode_server_msg};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 25565);
    let msg = ServerMsg::TargetAddr(addr);

    let mut buf = Vec::new();
    encode_server_msg(&msg, &mut buf);

    let (decoded, consumed) = decode_server_msg(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded, msg, "Roundtrip should preserve address");
    assert_eq!(consumed, 8, "IPv4 message should be 8 bytes");
}

#[test]
fn tunnel_ipv6_target_addr_roundtrip() {
    // Test: IPv6 target address encoding/decoding
    use tun::{ServerMsg, decode_server_msg, encode_server_msg};

    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        8080,
    );
    let msg = ServerMsg::TargetAddr(addr);

    let mut buf = Vec::new();
    encode_server_msg(&msg, &mut buf);

    let (decoded, consumed) = decode_server_msg(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded, msg, "Roundtrip should preserve IPv6 address");
    assert_eq!(consumed, 20, "IPv6 message should be 20 bytes");
}

#[test]
fn tunnel_session_offer_roundtrip() {
    // Test: SessionOffer message encoding/decoding
    use tun::{ServerMsg, decode_server_msg, encode_server_msg};

    let msg = ServerMsg::SessionOffer([30u8; 32]);

    let mut buf = Vec::new();
    encode_server_msg(&msg, &mut buf);

    let (decoded, consumed) = decode_server_msg(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded, msg, "Roundtrip should preserve session offer");
    assert_eq!(consumed, 33, "SessionOffer message should be 33 bytes");
}


#[test]
fn tunnel_protocol_error_handling() {
    // Test: Protocol errors are handled correctly
    use tun::{decode_agent_hello, decode_server_msg, TunnelError};

    // Invalid magic bytes
    let mut buf = vec![0u8; 38];
    buf[0] = b'X';
    let result = decode_agent_hello(&buf);
    assert!(matches!(result, Err(TunnelError::InvalidMagic)));

    // Invalid message kind
    let bad_msg = vec![99u8; 10];
    let result = decode_server_msg(&bad_msg);
    assert!(matches!(result, Err(TunnelError::InvalidIntent(99))));

    // Invalid address family
    let mut bad_addr = vec![2u8, 99u8, 0, 80]; // TargetAddr with family 99
    bad_addr.extend_from_slice(&[0u8; 4]);
    let result = decode_server_msg(&bad_addr);
    assert!(matches!(result, Err(TunnelError::InvalidAddrFamily(99))));
}

#[test]
fn tunnel_buffer_handling() {
    // Test: Protocol correctly handles incomplete/truncated buffers
    use tun::{decode_agent_hello, decode_server_msg};

    // Buffer too short for AgentHello header
    let short_buf = vec![b'L', b'T', b'U', b'N']; // Only magic, no header
    let result = decode_agent_hello(&short_buf);
    assert!(result.unwrap().is_none(), "Should return None for incomplete buffer");

    // Buffer too short for ServerMsg
    let msg_header = vec![1u8]; // Only message kind
    let result = decode_server_msg(&msg_header);
    assert!(result.unwrap().is_none(), "Should return None for incomplete message");
}
