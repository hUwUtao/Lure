# TCP Tunnel (Beta)

This document describes the pure-TCP tunnel agent flow and how Lure integrates with it.

## Purpose

- NAT passthrough for routes marked as tunnel-enabled.
- No encryption or auth beyond a shared 32-byte token.
- Tunnel agent connects to Lure ingress and reverse-proxies to the target.

## Status

**Beta-Ready**: Session timeout cleanup, comprehensive testing, and observability implemented.

**Not yet production-ready**: Keep-alive protocol extension (deferred to v2).

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

### Token Generation

Generate a cryptographically secure 32-byte token. Examples:

```bash
# Using openssl
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Store tokens securely in your configuration. Each tunnel route should have a unique token.

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

## Security Considerations

### What is Protected
- **Token authentication**: Each tunnel route uses a 32-byte token to authenticate agents.
- **Session isolation**: Session tokens are cryptographically random and checked on every connection.
- **Token mismatch detection**: Attempting to connect with a mismatched token is logged and rejected.

### What is NOT Protected
- **No encryption**: Tunnel traffic is sent in plain TCP. Use TLS/DTLS at the application layer or network layer (VPN/WireGuard).
- **No authentication on subsequent connections**: After the initial token validation, subsequent client traffic is not authenticated.
- **No integrity checks**: Network packets can be modified in flight. Rely on application-level integrity (e.g., Minecraft protocol hash).
- **Token exposure**: If the token is compromised, any agent can impersonate the tunnel. Treat tokens like credentials.

### Best Practices
1. **Use HTTPS/TLS for sensitive applications** - Don't rely on the tunnel for encryption.
2. **Rotate tokens regularly** - Change tunnel tokens periodically (quarterly or after personnel changes).
3. **Use VPN for additional network security** - Combine with WireGuard or Tailscale for defense in depth.
4. **Monitor tunnel connections** - Enable debug logging and monitor for unauthorized connection attempts.
5. **Limit access to configuration** - Store `settings.toml` securely with restricted file permissions.

## Operational Limits and Timeouts

### Session Timeout (30 seconds)
- A client must complete the Minecraft login handshake within 30 seconds after receiving a SessionOffer.
- If no agent connects to accept the session within 30 seconds, the session expires automatically.
- Expired sessions are cleaned up every 5 seconds. Metrics are available in debug logs.

### Keep-Alive
- **Not currently supported** - If the agent connection is idle, it may be closed by network infrastructure.
- **Workaround**: Design agents to reconnect periodically or on any connection error.
- **Future**: Keep-alive will be added in protocol v2.

### Maximum Pending Sessions
- **Default limit**: 10,000 pending sessions per Lure instance.
- **Rationale**: Prevents unbounded memory growth from clients that accept but never complete login.
- **Behavior**: New session offers are rejected if the limit is exceeded; clients receive a "tunnel session limit exceeded" error.

## Observability

### Logging

Tunnel events are logged using the standard Lure logger:

```
[INFO] Tunnel agent registered: token=8f
[DEBUG] Tunnel session offered: token=8f target=10.0.0.12:25565
[DEBUG] Tunnel session accepted: token=8f target=10.0.0.12:25565
[DEBUG] Tunnel agent disconnected: token=8f
[DEBUG] Tunnel session expired: session=3c
[WARN] Tunnel agent not found: token=8f session=3c
[WARN] Tunnel session not found: session=3c
[WARN] Tunnel token mismatch (unauthorized accept attempt): agent=8f session=3c
[ERROR] Tunnel session error during session handling (target 10.0.0.12:25565): ...
```

Enable debug logging to see session lifecycle events:

```bash
RUST_LOG=debug lure start
```

### Metrics

The following metrics are exposed:

- `tunnel.agents.registered` (gauge) - Number of connected tunnel agents
- `tunnel.agents.connected` (gauge) - Number of agents with active listening
- `tunnel.sessions.offered` (counter) - Total sessions offered to agents
- `tunnel.sessions.accepted` (counter) - Total sessions accepted by agents
- `tunnel.sessions.timeout` (counter) - Total sessions that expired
- `tunnel.sessions.failed` (counter) - Total session failures

## Troubleshooting

### Agent cannot connect to Lure

**Symptoms**: Agent reports connection refused or timeout.

**Diagnosis**:
1. Verify Lure is listening on the correct address: `netstat -tlnp | grep lure`
2. Check firewall rules: `sudo iptables -L -n` or cloud security group
3. Verify network connectivity: `ping <lure-server>`

**Solution**: Open the port in firewall and verify connectivity.

### Client connects but hangs during handshake

**Symptoms**: Client logs in, but game freezes on "Logging in...".

**Diagnosis**:
1. Check agent logs: Are there any connection errors?
2. Check Lure logs for "session timeout" or "agent disconnected"
3. Enable debug logging on both sides

**Solution**:
1. Verify the endpoint address is correct: `telnet <endpoint>`
2. Check agent is still connected: Look for "Tunnel agent registered" in logs
3. Increase timeout if needed (currently hard-coded to 30 seconds)

### "Tunnel session limit exceeded" error

**Symptoms**: Clients receive a disconnect with message "tunnel session limit exceeded".

**Diagnosis**:
1. Check if legitimate traffic spike or attack
2. Monitor agent connections: Are agents accepting sessions?

**Solution**:
1. Increase pending session limit (requires code change)
2. Add rate limiting to clients
3. Investigate why agents are not accepting sessions

### Agent disconnects unexpectedly

**Symptoms**: Agent logs show successful registration, then unexpected disconnection.

**Diagnosis**:
1. Check network stability: Look for packet loss or timeout errors
2. Check Lure logs for write errors or protocol violations
3. Verify agent correctly handles connection drops

**Solution**:
1. Implement agent reconnect logic (exponential backoff)
2. Add keep-alive heartbeats (future feature)
3. Use persistent network (WireGuard/VPN) for reliability

## Example Deployment

### Agent on internal network, Lure on public internet

```
[Internal Network]
  Tunnel Agent (token: 8f1f2a3b...)
       |
       | (TLS/WireGuard recommended)
       |
    [Internet]
       |
   Lure Gateway
       |
   Minecraft Clients
```

**Agent startup**:
```bash
lure-agent \
  --server proxy.example.com:25567 \
  --token 8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b \
  --listen 0.0.0.0:25565
```

**Route configuration**:
```toml
[[route]]
matcher = "behind-nat.example.com"
endpoint = "internal-server.local:25565"
priority = 0

[route.flags]
tunnel = true
tunnel_token = "8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"
```

### Multi-agent for redundancy

Deploy multiple tunnel agents, each with the same token. Lure will send session offers to all registered agents; the first to connect wins.

```bash
# Agent 1
lure-agent --server proxy.example.com:25567 --token ABC123... --listen 0.0.0.0:25565

# Agent 2
lure-agent --server proxy.example.com:25567 --token ABC123... --listen 0.0.0.0:25565
```

## Notes

- Tunnel detection happens before decoding Minecraft handshake; if the magic
  bytes are not present, Lure proceeds with the normal handshake path.
- This is a simple coordination layer and does not provide encryption.
- Session timeouts are automatic and transparent to agents and clients.
