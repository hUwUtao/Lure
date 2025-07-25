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

## Philosophy

Multi-tenancy design model, that to using well serialized configuration not config-generation and reloading
(which prone gimmick at scale)

Gate(lite), which is a mature proxy for this purpose, but I wasn't able to make it work on this model.

## Features

- Customized routing with API control. *Currently, routes are loaded from RPC default_routes (see below)*
- Query with slight cache
- Multi-server & multi-host support
- Proxy Protocol (supported Paper-derived, Velocity and Bungeecord)
- Highly observable system
- Addon API (via RPC, see [Elysia implementation](https://github.com/hUwUtao/Lucky))
- Global threat control (WIP), with socket ratelimit, etc.

### Cutting edge

Future proof features, with considerations that some "unsafe" are fine. Project is using rustfmt nightly.
To extends features like runtime monitoring \(I have some jealousy with go that they have actually mature otlp).

### The coldest process

Optional [mimalloc](https://github.com/microsoft/mimalloc) crate feature allocator reduces CPU usage (4% → 1%) at the
cost of higher memory usage (~47MiB vs ~20MiB).

### Incompatibility

- Known gimmick to actual protocol-use is `viaproxy`. On 1.20.6 server, there such a behavior of packet disorder 
suspected because of async polling (or kind of?)

| Server Version | Client Version   | Observed                                                                            |
|----------------|------------------|-------------------------------------------------------------------------------------|
| Purpur 1.20.6  | 1.20.6           | Ok                                                                                  |
| ^              | 1.21.1-4         | Client is disconected by clientbound-entity_remove packet 1xx packet overestimation |
| Paper 1.20.6   | 1.21.5+          | ^                                                                                   |   
| ^              | 1.20.6, 1.21.1-4 | Ok                                                                                  |

## Credits

Original implementor [sammwyy](https://github.com/sammwyy)