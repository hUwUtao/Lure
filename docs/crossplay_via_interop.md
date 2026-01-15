# Crossplay ViaProxy / Geyser interop notes

## Hostname token preservation

- ViaProxy rewrites handshake hostnames by default. This will strip `lurex.<token>.<host>`.
- Option: disable or patch `rewrite-handshake-packet` so the hostname is passed through.
- Option: wrap ViaProxy with a pre-handshake proxy that restores or injects the token.

## Geyser token parsing

- Geyser does not parse custom tokens from HAProxy PROXY TLVs.
- Token should be parsed from the Java handshake hostname at ViaGeyserProxy entry.
- Implement hostname parsing in ViaGeyserProxy and strip token before loopback to Lure.

## IP forwarding

- ViaProxy can emit HAProxy PROXY headers; backend TLV 0xE0 is used for client version.
- Geyser supports PROXY protocol for UDP but ignores TLVs.
- If client IP must be preserved end-to-end, we need one of:
  - Patch Geyser to read custom TLVs or hostname token to extract IP.
  - Introduce a dedicated forwarding channel outside of the token payload.

## Hotpatch strategy

- Preferred: patch ViaProxy rewrite path and ViaGeyserProxy hostname handling.
- Alternative: run a wrapper proxy that re-injects tokens at the TCP handshake boundary.
