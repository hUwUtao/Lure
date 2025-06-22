<p align=center>
  <img src="https://github.com/sammwyy/Lure/raw/main/assets/icon@64.png"/>
<p>

<h1 align=center>Lure</h1>
<p align=center>The true next-gen <strike>L7</strike> L4 minecraft proxy and load balancer. Built in Rust, Tokio and Valence.</p>

## Purpose

Route to Minecraft server with basic HAProxy protocol

## Why?

This fork is meant to strip down the "L7" of the proxy to left with a "L4" proxy that only route to server. It support match routing, ping-passthrough (with ability to overrides too), placeholder, proxy-proto and so more. Also make core dependencies like valence up-to-date

This project (fork) is meant to "replace" [Gate](https://gate.minekube.com/). Turns out, Gate is sucks at actually applying config live.

~~Rust is a powerful programming language and a great development environment with a large and growing ecosystem. The efficiency of the applications built in it is such that several companies are moving their products to this technology.~~ I used to love this 🥷 language

~~Proxies built in Java store too much player data in memory. They have unneeded functions and complex API systems that in the end make a simple proxy whose job is to carry packets from one point to another become an entire server.~~ No you want to use some proxy like Velocity. You need it to compatible with plugins that actually in one ecosystem. This project doesn't affect your stack.

~~Lure came along to fix that.~~

## 📝 To Do

- [ ] Configuration system. (redo)
- [X] ~~MoTD.~~
- [X] ~~Favicon.~~
- [X] Proxy client to a server.
- [X] Multiple servers.
- [X] Multiple hosts.
- [X] ~~Compression.~~
- [X] ~~Online mode.~~ *Basically not effective*
- [ ] ~~Player limit.~~
- [x] Query Forwarding with debounce cache
- [x] IP Forwarding. (Proxy protocol is now supported. Paper derivatives, Velocity, Bungeecord has built in support)
- [ ] ~~Switch between servers.~~
- [ ] ~~Plugin channels.~~
- [ ] ~~Internal Commands.~~
- [ ] ~~Addon API.~~ Route store control API
- [x] Metrics
- [ ] Ping fallback/override (free stuff comes with ads, who doesn't love that)
- [ ] `LoginHello` snooping (valence's `LoginHelloC2S` decoder currently working improperly)
- [ ] Socket ratelimit
- [ ] Anomaly tracking
- [ ] Be evil

## Credits

Original implementor [sammwyy](https://github.com/sammwyy)