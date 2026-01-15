# Crossplay Backloop Prototype

## Flow Summary

- ViaProxy (Java clients)
  - Client -> Lure (Java listen)
  - No token: route to ViaProxy
  - Tokened: Lure injects token into hostname and routes to ViaGeyserProxy
  - ViaGeyserProxy parses token and loops back to Lure Java listen -> endpoint

- ViaProxy + Bedrock (endpoints treated as Java)
  - Bedrock client -> Lure (Bedrock UDP)
  - Lure forwards to ViaGeyserProxy with token injected into the Java handshake hostname
  - ViaGeyserProxy parses token and loops back to Lure Java listen -> endpoint

- Bedrock direct split
  - Endpoints expose TCP + UDP on the same port number
  - Lure Java listens on TCP, Lure Bedrock listens on UDP

## Token Contract (Hostname)

- Prefix format: `lurex.<token>.<host>`
- `<token>` is base64url, payload + Ed25519 signature
- Payload: `version(1) | issued_at(u64) | route_len(u8) | route_bytes`
- The token is signed using Lure's `proxy_signing_key`

## Integration Points

- Inbound:
  - Lure parses `lurex.<token>` in the handshake hostname
  - If valid, uses token route to resolve, and strips token before proxying
- Outbound:
  - If route flag `inject_token` is set, Lure injects token into hostname before connecting to ViaGeyserProxy

## Sidecar Manager

- `SidecarManager` spawns, stops, and restarts external processes
- Intended for ViaProxy + ViaGeyserProxy supervision
- `update_ab` performs an A/B rollout, promoting a new instance and optionally draining the old one
- Instances are named `<group>-<slot>-<generation>` to avoid accidental reuse during overlapping updates
- `group_status` reports active/draining slots and pids; `reap_exited` prunes crashed instances
- `spawn_reaper` runs a periodic reaper to clean up exited sidecars and empty groups
- `finish_drain` terminates the draining instance early once sessions are gone

## Sidecar Endpoints

- Route endpoints can use `sidecar.<group>:<port>` to defer resolution to the crossplay supervisor.
- The supervisor swaps the endpoint address to the active A/B listen address before connecting.

## Bedrock Notes

- Bedrock routing uses the login ServerAddress (from JWT) as-is for route resolution.
- Bedrock does not parse or inject `lurex` tokens; loopback tokens are only used on the Java handshake path.

## Next Work

- Wire config/CLI for `inject_token` and crossplay flags
- Hotpatch path: wrapper proxy for hostname rewrite or Java agent hooks
