<p align="center">
  <img src="https://github.com/sammwyy/Lure/raw/main/assets/icon@64.png" alt="Lure Icon"/>
</p>

<h1 align="center">Lure</h1>
<p align="center"><em>The native Minecraft reverse proxy that works.</em></p>

---

## Contents

- [What It Is](#what-it-is)
- [Performance tuning](#performance-tuning)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running (I/O Backends)](#running-io-backends)
- [Tunneling (Beta)](#tunneling-beta)
- [Env Vars](#env-vars)
- [Compatibility / Quirks](#compatibility--quirks)
- [Development](#development)
- [Credits](#credits)

## What It Is

Lure is a TCP proxy that speaks enough Minecraft to proxy and filter<sub>(not yet)</sub> connections without
turning the config into a second programming language.

Its only purpose is to correctly delivers the correct Minecraft server to the client, however it
could be used to against quite the basic threats.

Can be configured with a yet-not-quite-friendly controller. However, we have a nice GUI to actually
control. If you really interested, you can be the early-adopter by contacting Discord @stdpi.

## Performance tuning

You can choose one of the connection backends that suits your use.

- **tokio**: Stable, quite fast polling and scales on multiple cores.
- **epoll**: Beta (Linux-only), the way HAProxy delivers million packets. Enable with `LURE_IO_EPOLL=1`
- **tokio-uring**: failed to perform under real stress even seems stable. Enable with `LURE_IO_URING=1` (**deprecated**, please don't use)

## Features

- Multi-route and multi-endpoint routing (single or multiple matchers/endpoints), load balancing
- Optional RPC control plane for orchestration (see [Lucky](https://github.com/hUwUtao/Lucky))
- PROXY protocol support, with signing authorization from proxy, implemented with [BetterProxyProtocol](https://github.com/LangDuaMC/BetterProxyProtocol)
- OTEL metrics observation
- Basic connection rate limiting, and risky IP filtering in the future.
- TCP tunnel agent (beta) to connect with the most efficient overhead

## Quick Start

```bash
cargo run
```

Reads `settings.toml` from the current directory. If it does not exist, Lure will generate one.
The generated default binds to `0.0.0.0:25577`.

Reload config on `SIGCONT`:

```bash
kill -CONT <pid>
```

Optional RPC backend (orchestration): set `LURE_RPC`.

Telemetry: set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable OTEL export.

## Configuration

`settings.toml` is plain TOML. No generators. No templates. No "just run the installer".

Notes:
- The config key is spelled `proxy_procol` (typo preserved for compatibility).

Minimal example:

```toml
inst = "main"
bind = "0.0.0.0:25577"
proxy_procol = false
max_conn = 65535
cooldown = 3

[strings]
ROUTE_NOT_FOUND = "route not found"
SERVER_OFFLINE = "server offline"

[[route]]
matchers = ["mc.acme.co", "play.acme.co"]
endpoints = ["10.0.0.10:25565", "10.0.0.11:25565"]
priority = 0

[route.flags]
proxy_protocol = true
preserve_host = true
auth_mode = "protected"

[[route]]
matcher = "eu.acme.co"
endpoint = "10.0.1.10:25565"
priority = 0

[route.flags]
proxy_protocol = true
auth_mode = "public"
```

## Running (I/O Backends)

Default is Tokio:

```bash
cargo run
```

Epoll backend (beta, Linux-only):

```bash
LURE_IO_EPOLL=1 cargo run
```

tokio-uring (not recommended; "failed experiment"):

```bash
LURE_IO_URING=1 cargo run --features uring
```

## Tunneling (Beta)

Need NAT passthrough? Lure can hand a connection to a tunnel agent that lives inside the network.

- Docs: `docs/tunnel.md`
- Security model: only to traverse NAT. yet encryptions needed, as internet is not that hell scary...

Route example:

```toml
[[route]]
matcher = "behind-nat.example.com"
endpoint = "10.0.0.12:25565"
priority = 0
tunnel_token = "8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb" # lowkey not real token

[route.flags]
tunnel = true
```

Then run the agents (sign the secret to get token that contains public so it authenticates):

```sh
tunure agent endpoint:25565 -t a1b2c3d4e5f6:8f1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f00112233445566778899aabb
```

## Env Vars

- `LURE_RPC`: RPC backend URL (optional)
- `LURE_PROXY_SIGNING_KEY`: base64 Ed25519 private key for signing proxy headers (optional)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: enable OTEL export when set
- `LURE_IO_EPOLL=1`: enable epoll backend (beta)
- `LURE_IO_URING=1`: enable tokio-uring backend (not recommended; requires `--features uring`)

## Compatibility / Quirks

- Works with old clients (1.7+) and includes Forge (FML) handshake handling.
- PROXY protocol support is v2.
- If you enable proxy protocol, also enable it on anything behind the proxy that needs to parse it
  (Paper/Velocity/Bungee/Geyser, etc).

## Development

- Build: `cargo build`
- Run: `cargo run`
- Test: `cargo test`
- Format: `cargo fmt`

## Credits

- Original implementor: [sammwyy](https://github.com/sammwyy)
