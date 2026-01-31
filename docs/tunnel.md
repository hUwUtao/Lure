# TCP Tunnel (Incubation)

This document describes the pure-TCP tunnel agent flow and how Lure integrates with it.

## Purpose

- NAT passthrough for routes marked as tunnel-enabled.
- No encryption or auth beyond a shared 32-byte token.
- Tunnel agent connects to Lure ingress and reverse-proxies to the target.

## Route Configuration

Add tunnel flags and a 32-byte token to a route in `settings.toml`.

```toml
[[route]]
matcher = "tunnel.example.com"
endpoint = "10.0.0.12:25565"
priority = 0

[route.flags]
tunnel = true

# 32-byte token as hex (64 chars) or base64
# tunnel_token = "8f1f..."
# tunnel_token = "s3Iu3RkV..."
```

## Tunnel Wire Protocol

All tunnel connections begin with a fixed hello frame:

- Magic: `LTUN` (4 bytes)
- Version: `1` (1 byte)
- Intent: `1` = listen, `2` = connect (1 byte)
- Token: 32 bytes
- Session: 32 bytes (only for intent=connect)

### Server Messages

After receiving a tunnel hello, the server can send:

- SessionOffer: `0x01` + 32-byte session token
- TargetAddr: `0x02` + addr family + port + IP
  - family `4`: 1 byte, port 2 bytes (be), IPv4 4 bytes
  - family `6`: 1 byte, port 2 bytes (be), IPv6 16 bytes

## End-to-End Flow

1) Agent connects to Lure ingress with intent=listen and token.
2) Client connects normally (Minecraft handshake + login).
3) If the resolved route has `tunnel` flag and a valid `tunnel_token`, Lure:
   - generates a session token
   - sends SessionOffer to the active agent
4) Agent reconnects with intent=connect, token, session token.
5) Lure responds with TargetAddr (the resolved backend address).
6) Lure bridges client stream to agent stream and forwards:
   - raw handshake
   - raw login start
   - any pending buffered bytes

## Notes

- Tunnel detection happens before decoding Minecraft handshake; if the magic
  bytes are not present, Lure proceeds with the normal handshake path.
- This is a simple coordination layer and does not provide encryption.
