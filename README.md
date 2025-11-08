<p align="center">
  <img src="https://github.com/sammwyy/Lure/raw/main/assets/icon@64.png" alt="Lure Icon"/>
</p>

<h1 align="center">Lure</h1>
<p align="center"><em>A modern Minecraft Layer 4 proxy and load balancer built with Rust, Tokio, and Valence.</em></p>

---

## Overview

**Lure** is a sophisticated, but lightweight enough, high-performance Layer 4 (L4) proxy for Minecraft.
It reach high performance with

- Fast tokio socket polling
- Fast first-handshake deserialization
- Async session handling

### Performance

Gate vs Lure, tested from VN to SG, with Wifi latency. 

![Gate: 96ms; Lure: 16ms](/assets/thicc.png)

<sub>*Lure actually give off uneven result with random spike, while Gate keeps a stable number, a quite lower than the peak of Lure</sub>

## Philosophy

Multi-tenancy design model, that to using well serialized configuration not config-generation and reloading
(which prone gimmick at scale)

Gate(lite), which is a mature proxy for this purpose, but I wasn't able to make it work on this model.

## Features

- Provision with an API backend for orchestration (via RPC, see [Elysia implementation](https://github.com/hUwUtao/Lucky))
- Multi-server & multi-host support
- Proxy Protocol (supported Paper-derived, Velocity and Bungeecord)
- Highly observable system through OTEL
- Global threat control (WIP), with socket ratelimit, etc.

### Cutting edge

Future proof features, with considerations that some "unsafe" are fine. Project is using rustfmt nightly.
To extends features like runtime monitoring \(I have some jealousy with go that they have actually mature otlp).

### The coldest process

Optional [mimalloc](https://github.com/microsoft/mimalloc) crate feature allocator reduces CPU usage (4% → 1%) at the
cost of higher memory usage (~47MiB vs ~20MiB).

### Compatibility

- Guaranteed to work with 1.7+
- Since HaProxyProtocol plaintext is not very common, only v2 is supported, most immplemented.
- FML (Forge) Handshake support is added

### Quirks

- TL*uncher Guard seemingly causing trouble
- Watch for any back-connect plugin like Geyser if proxy protocol is enabled. You have to enable both `proxy_protocol` key from desired plugin/paper config + geyser config
- FML server must present "PreserveHost" (TODO: to support without)
- 0.1.2 -> 0.1.3 has major config layout changes

### Configuration

The server can now be configured stand-alone without the need of RPC backend

```toml
# settings.toml
inst = "main"
bind = "0.0.0.0:25577"
proxy_procol = false
# key name to be changed
max_conn = 65535
cooldown = 3 
# ---

[strings]
# vendor specific, all keys optional
MESSAGE_CANNOT_CONNECT = "Cannot connect to destinated server:"
ERROR = "Error"
SERVER_OFFLINE = "Server is offline :("
ROUTE_NOT_FOUND = "The destinated server is not registered"
SERVER_LIST_BRAND = "oops"

[[route]]
matchers = ["mc.acme.co", "play.acme.co"]
preserve_host = true # false by default
proxy_protocol = true # false by default
endpoints = ["craft-clust-1001.acme.co:25565", "craft-clust-1002.acme.co:25565"]

[[route]]
matcher = "eu.acme.co"
preserve_host = false
proxy_protocol = true
endpoint = "craft-clust-1001.acme.co:25565"
```

> To configure RPC url, use `LURE_RPC` env

## Credits

Original implementor [sammwyy](https://github.com/sammwyy)
