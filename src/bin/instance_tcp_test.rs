use std::{
    collections::VecDeque,
    env,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use log::error;
use lure::{
    config::{LureConfig, RouteConfig, RouteFlagsConfig, TokenEntry, TunnelConfig},
    lure::Lure,
    sock,
    utils::leak,
};
use tokio::sync::{oneshot, watch};

const DEFAULT_DURATION_SECS: u64 = 5;
const DEFAULT_WARMUP_SECS: u64 = 1;
const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_PIPELINE: usize = 8;
const DEFAULT_PAYLOAD: usize = 1024;

const FRAME_MAGIC: [u8; 4] = *b"LRTT";

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Plain,
    Tunnel,
    Both,
}

impl Scenario {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "plain" => Ok(Self::Plain),
            "tunnel" => Ok(Self::Tunnel),
            "both" => Ok(Self::Both),
            other => Err(anyhow::anyhow!(
                "invalid --scenario {other} (expected plain|tunnel|both)"
            )),
        }
    }
}

#[derive(Clone)]
struct SuiteConfig {
    duration: Duration,
    warmup: Duration,
    concurrency: usize,
    pipeline: usize,
    payload: usize,
    host: String,
    scenario: Scenario,
}

#[derive(Clone, Copy)]
struct OpSample {
    total_ns: u64,
}

struct ThreadResult {
    ops: u64,
    bytes: u64,
    samples: Vec<OpSample>,
}

struct RunResult {
    duration: Duration,
    ops: u64,
    bytes: u64,
    samples: Vec<OpSample>,
}

#[derive(Clone)]
struct LatencyStats {
    count: usize,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cfg = parse_args()?;
    let backend = sock::backend_selection();

    println!("backend: {:?} ({})", backend.kind, backend.reason);
    println!(
        "config: scenario={:?} duration={}s warmup={}s concurrency={} pipeline={} payload={}B host={}",
        cfg.scenario,
        cfg.duration.as_secs(),
        cfg.warmup.as_secs(),
        cfg.concurrency,
        cfg.pipeline,
        cfg.payload,
        cfg.host
    );

    if cfg.payload < 32 {
        anyhow::bail!("--payload must be >= 32");
    }
    if cfg.pipeline == 0 {
        anyhow::bail!("--pipeline must be > 0");
    }
    if cfg.concurrency == 0 {
        anyhow::bail!("--concurrency must be > 0");
    }

    match backend.kind {
        sock::BackendKind::Uring => net::sock::uring::start(async {
            let local = tokio::task::LocalSet::new();
            local.run_until(async move { run_suite(cfg).await }).await
        }),
        sock::BackendKind::Epoll | sock::BackendKind::Tokio => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let local = tokio::task::LocalSet::new();
            rt.block_on(local.run_until(async move { run_suite(cfg).await }))
        }
    }
}

async fn run_suite(cfg: SuiteConfig) -> anyhow::Result<()> {
    let echo = FramedEchoServer::start(cfg.payload)?;

    let direct = run_direct(&cfg, echo.addr)?;
    println!();
    println!("direct (baseline):");
    report(&direct);

    if cfg.warmup.as_secs() > 0 {
        // Warmup direct path only; it's stable and avoids hiding regressions in Lure runs.
        let _ = run_direct(
            &SuiteConfig {
                duration: cfg.warmup,
                warmup: Duration::from_secs(0),
                ..cfg.clone()
            },
            echo.addr,
        )?;
    }

    // Start a single in-process Lure instance and reconfigure between scenarios.
    let plain_config = LureConfig {
        inst: "instance_tcp_test".to_string(),
        bind: "127.0.0.1:0".to_string(),
        route: vec![RouteConfig {
            matcher: Some(cfg.host.clone()),
            matchers: vec![],
            endpoint: Some(echo.addr.to_string()),
            endpoints: vec![],
            priority: 0,
            flags: None,
            tunnel_token: None,
        }],
        ..Default::default()
    };

    let lure = leak(Lure::new(plain_config.clone()));
    lure.sync_routes_from_config().await?;
    lure.sync_tunnel_tokens_from_config().await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::task::spawn_local(async move {
        lure.start_with_shutdown(Some(ready_tx), shutdown_rx).await
    });
    let lure_addr = tokio::time::timeout(Duration::from_secs(2), ready_rx)
        .await
        .context("timeout waiting for lure bind")??;

    let mut plain = None;
    let mut tunneled = None;

    let run_lure_load = |cfg: SuiteConfig,
                         lure_addr: SocketAddr,
                         record: bool,
                         duration: Duration|
     -> tokio::task::JoinHandle<anyhow::Result<RunResult>> {
        tokio::task::spawn_blocking(move || {
            run_client_load(
                &cfg,
                lure_addr,
                ConnectPlan::LureLogin {
                    host: cfg.host.clone(),
                },
                record,
                duration,
            )
        })
    };

    if matches!(cfg.scenario, Scenario::Plain | Scenario::Both) {
        lure.reload_config(plain_config.clone()).await?;
        let r = run_lure_load(cfg.clone(), lure_addr, true, cfg.duration).await??;
        plain = Some(r);
    }

    if matches!(cfg.scenario, Scenario::Tunnel | Scenario::Both) {
        // Token registry + route token.
        let key_id: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let secret: [u8; 32] = [0x11; 32];
        let mut route_token = [0u8; 32];
        route_token[..8].copy_from_slice(&key_id);
        route_token[8..].copy_from_slice(&[0x22; 24]);

        let mut tunnel_config = plain_config.clone();
        tunnel_config.tunnel = TunnelConfig {
            token: vec![TokenEntry {
                key_id: hex::encode(key_id),
                secret: hex::encode(secret),
                name: Some("instance_tcp_test".to_string()),
                zone: None,
            }],
        };
        tunnel_config.route[0].flags = Some(RouteFlagsConfig {
            tunnel: true,
            auth_mode: "protected".to_string(),
            ..Default::default()
        });
        tunnel_config.route[0].tunnel_token = Some(hex::encode(route_token));

        lure.reload_config(tunnel_config).await?;

        // Start agent and wait for registration before driving load.
        let (agent_stop_tx, agent_stop_rx) = watch::channel(false);
        let (agent_ready_tx, agent_ready_rx) = oneshot::channel();
        let agent = tokio::task::spawn_local(async move {
            run_tun_agent(lure_addr, key_id, secret, agent_stop_rx, agent_ready_tx).await
        });
        let _ = tokio::time::timeout(Duration::from_secs(2), agent_ready_rx)
            .await
            .context("agent registration timeout")??;

        let r = run_lure_load(cfg.clone(), lure_addr, true, cfg.duration).await??;
        tunneled = Some(r);

        let _ = agent_stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), agent)
            .await
            .ok();
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .ok();

    if let Some(r) = &plain {
        println!();
        println!("lure (plain route):");
        report(r);
        println!("overhead vs direct (ms):");
        report_overhead(&direct, r);
    }

    if let Some(r) = &tunneled {
        println!();
        println!("lure (tunnel route + agent):");
        report(r);
        println!("overhead vs direct (ms):");
        report_overhead(&direct, r);
    }

    if let (Some(p), Some(t)) = (&plain, &tunneled) {
        println!();
        println!("tunnel overhead vs plain (ms):");
        report_overhead(p, t);
    }

    echo.stop();
    Ok(())
}

fn run_direct(cfg: &SuiteConfig, backend_addr: SocketAddr) -> anyhow::Result<RunResult> {
    run_client_load(cfg, backend_addr, ConnectPlan::Direct, true, cfg.duration)
}

#[derive(Clone)]
enum ConnectPlan {
    Direct,
    LureLogin { host: String },
}

fn run_client_load(
    cfg: &SuiteConfig,
    addr: SocketAddr,
    plan: ConnectPlan,
    record_samples: bool,
    duration: Duration,
) -> anyhow::Result<RunResult> {
    let deadline = Instant::now() + duration;
    let (tx, rx) = std::sync::mpsc::channel();

    for _ in 0..cfg.concurrency {
        let tx = tx.clone();
        let plan = plan.clone();
        let payload = cfg.payload;
        let pipeline = cfg.pipeline;
        thread::spawn(move || {
            let r = client_worker(addr, plan, payload, pipeline, deadline, record_samples);
            let _ = tx.send(r);
        });
    }
    drop(tx);

    let start = Instant::now();
    let mut ops = 0u64;
    let mut bytes = 0u64;
    let mut samples = Vec::new();

    for r in rx {
        let r = r?;
        ops += r.ops;
        bytes += r.bytes;
        if record_samples {
            samples.extend(r.samples);
        }
    }

    Ok(RunResult {
        duration: start.elapsed(),
        ops,
        bytes,
        samples,
    })
}

fn client_worker(
    addr: SocketAddr,
    plan: ConnectPlan,
    payload: usize,
    pipeline: usize,
    deadline: Instant,
    record_samples: bool,
) -> anyhow::Result<ThreadResult> {
    let mut stream = TcpStream::connect(addr)?;
    let _ = stream.set_nodelay(true);
    // Fail fast if the proxy path stops returning data.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    match plan {
        ConnectPlan::Direct => {}
        ConnectPlan::LureLogin { host } => {
            // Get Lure into passthrough mode.
            let (hs, login) = mc_handshake_and_login(&host)?;
            stream.write_all(&hs)?;
            stream.write_all(&login)?;
        }
    }

    let mut seq = 0u64;
    let mut ops = 0u64;
    let mut samples = Vec::new();

    let mut write_buf = vec![0u8; payload];
    let mut read_buf = vec![0u8; payload];

    // FIFO expectation: we expect responses in the same order we sent.
    let mut pending: VecDeque<(u64, u64, u64)> = VecDeque::with_capacity(pipeline + 1); // (seq, send_ts_ns, send_start_ns)

    loop {
        let now = Instant::now();
        if now >= deadline && pending.is_empty() {
            break;
        }

        while pending.len() < pipeline && Instant::now() < deadline {
            let send_ts_ns = get_nanos();
            fill_frame(&mut write_buf, seq, send_ts_ns);

            let send_start_ns = get_nanos();
            stream.write_all(&write_buf)?;
            pending.push_back((seq, send_ts_ns, send_start_ns));

            seq = seq.wrapping_add(1);
        }

        while !pending.is_empty() {
            let (expect_seq, expect_send_ts_ns, send_start_ns) = pending.pop_front().unwrap();
            let _recv_start_ns = get_nanos();
            stream.read_exact(&mut read_buf)?;
            let recv_end_ns = get_nanos();

            validate_frame(&read_buf, expect_seq, expect_send_ts_ns)
                .with_context(|| format!("frame validation failed (seq={expect_seq})"))?;

            ops += 1;
            if record_samples {
                samples.push(OpSample {
                    total_ns: recv_end_ns.saturating_sub(send_start_ns),
                });
            }
        }
    }

    Ok(ThreadResult {
        ops,
        bytes: ops * payload as u64 * 2,
        samples,
    })
}

fn mc_handshake_and_login(host: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // Use a protocol version below UUID/sig extensions for LoginStartC2s encoding.
    let hs = net::HandshakeC2s {
        protocol_version: 758,
        server_address: host,
        server_port: 25565,
        next_state: net::HandshakeNextState::Login,
    };
    let login = net::LoginStartC2s {
        username: "tcp_test_user",
        profile_id: None,
        sig_data: None,
    };

    let mut hs_raw = Vec::new();
    net::encode_packet(&mut hs_raw, &hs)?;
    let mut login_body = Vec::new();
    login.encode_body_with_version(&mut login_body, hs.protocol_version)?;
    let mut login_raw = Vec::new();
    net::encode_raw_packet(&mut login_raw, net::LoginStartC2s::ID, &login_body)?;
    Ok((hs_raw, login_raw))
}

// High-precision nanosecond timer using CLOCK_MONOTONIC.
fn get_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn fill_frame(buf: &mut [u8], seq: u64, send_ts_ns: u64) {
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4..12].copy_from_slice(&seq.to_be_bytes());
    buf[12..20].copy_from_slice(&send_ts_ns.to_be_bytes());
    let seed = (seq as u8) ^ (send_ts_ns as u8) ^ 0x5a;
    for (i, b) in buf[20..].iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).rotate_left((i % 7) as u32);
    }
}

fn validate_frame(buf: &[u8], expect_seq: u64, expect_send_ts_ns: u64) -> anyhow::Result<()> {
    if buf.len() < 20 {
        anyhow::bail!("short frame: {} bytes", buf.len());
    }
    if buf[..4] != FRAME_MAGIC {
        anyhow::bail!("bad magic");
    }
    let got_seq = u64::from_be_bytes(buf[4..12].try_into().unwrap());
    if got_seq != expect_seq {
        anyhow::bail!("out-of-order: got seq={got_seq} expect seq={expect_seq}");
    }
    let got_ts = u64::from_be_bytes(buf[12..20].try_into().unwrap());
    if got_ts != expect_send_ts_ns {
        anyhow::bail!("pair mismatch: got ts={got_ts} expect ts={expect_send_ts_ns}");
    }
    let seed = (expect_seq as u8) ^ (expect_send_ts_ns as u8) ^ 0x5a;
    for (i, b) in buf[20..].iter().enumerate() {
        let expect = seed.wrapping_add(i as u8).rotate_left((i % 7) as u32);
        if *b != expect {
            anyhow::bail!(
                "body mismatch at offset {}: got={} expect={}",
                20 + i,
                *b,
                expect
            );
        }
    }
    Ok(())
}

fn report(r: &RunResult) {
    let secs = r.duration.as_secs_f64().max(0.001);
    let ops_per_sec = r.ops as f64 / secs;
    let mib_per_sec = r.bytes as f64 / (1024.0 * 1024.0) / secs;

    println!("  ops: {}", r.ops);
    println!("  bytes: {}", r.bytes);
    println!("  duration: {secs:.3}s");
    println!("  ops/sec: {ops_per_sec:.2}");
    println!("  throughput: {mib_per_sec:.2} MiB/s");

    if r.samples.is_empty() {
        println!("  latency: (none)");
        return;
    }

    let s = latency_stats(&r.samples);
    println!("  latency (ms):");
    println!("    mean: {:.4}", s.mean_ms);
    println!("    p50: {:.4}", s.p50_ms);
    println!("    p95: {:.4}", s.p95_ms);
    println!("    p99: {:.4}", s.p99_ms);
    println!("    max: {:.4}", s.max_ms);
    println!("    samples: {}", s.count);
}

fn report_overhead(a: &RunResult, b: &RunResult) {
    if a.samples.is_empty() || b.samples.is_empty() {
        println!("  (missing samples)");
        return;
    }
    let as_ = latency_stats(&a.samples);
    let bs_ = latency_stats(&b.samples);
    println!("  p50: {:.4}", bs_.p50_ms - as_.p50_ms);
    println!("  p95: {:.4}", bs_.p95_ms - as_.p95_ms);
    println!("  p99: {:.4}", bs_.p99_ms - as_.p99_ms);
    println!("  mean: {:.4}", bs_.mean_ms - as_.mean_ms);
}

fn latency_stats(samples: &[OpSample]) -> LatencyStats {
    let count = samples.len();
    let mut ns: Vec<u64> = samples.iter().map(|s| s.total_ns).collect();
    ns.sort_unstable();

    let mut sum = 0f64;
    for s in samples {
        sum += s.total_ns as f64 / 1_000_000.0;
    }
    let mean_ms = sum / count as f64;

    LatencyStats {
        count,
        mean_ms,
        p50_ms: percentile_ms(&ns, 50.0),
        p95_ms: percentile_ms(&ns, 95.0),
        p99_ms: percentile_ms(&ns, 99.0),
        max_ms: (*ns.last().unwrap_or(&0) as f64) / 1_000_000.0,
    }
}

fn percentile_ms(sorted_ns: &[u64], pct: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * (sorted_ns.len() as f64 - 1.0)).round() as usize;
    sorted_ns[rank.min(sorted_ns.len() - 1)] as f64 / 1_000_000.0
}

struct FramedEchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

impl FramedEchoServer {
    fn start(frame_size: usize) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);

        let join = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        thread::spawn(move || framed_echo_loop(stream, frame_size));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { addr, stop, join })
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.join.join();
    }
}

fn framed_echo_loop(mut stream: TcpStream, frame_size: usize) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut pending = Vec::<u8>::new();

    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        pending.extend_from_slice(&buf[..n]);

        // Resync on magic; discard everything before magic, then echo whole frames.
        loop {
            if pending.len() < 4 {
                break;
            }
            let pos = if let Some(p) = find_magic(&pending) {
                p
            } else {
                // Keep last 3 bytes in case magic splits across reads.
                if pending.len() > 3 {
                    pending.drain(..pending.len() - 3);
                }
                break;
            };
            if pos > 0 {
                pending.drain(..pos);
            }
            if pending.len() < frame_size {
                break;
            }
            let frame: Vec<u8> = pending.drain(..frame_size).collect();
            if stream.write_all(&frame).is_err() {
                return;
            }
        }
    }
}

fn find_magic(hay: &[u8]) -> Option<usize> {
    hay.windows(4).position(|w| w == FRAME_MAGIC)
}

async fn run_tun_agent(
    ingress: SocketAddr,
    key_id: [u8; 8],
    secret: [u8; 32],
    mut stop_rx: watch::Receiver<bool>,
    ready_tx: oneshot::Sender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    // Register listener.
    let mut listener = tun::connect_agent(ingress).await?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let hmac = tun::compute_agent_hmac(&secret, &key_id, timestamp, tun::Intent::Listen, None);
    send_agent_hello(
        &mut listener,
        tun::AgentHello {
            version: tun::VERSION,
            intent: tun::Intent::Listen,
            key_id,
            timestamp,
            hmac,
            session: None,
        },
    )
    .await?;

    let _ = ready_tx.send(Ok(()));

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    loop {
        if *stop_rx.borrow() {
            break;
        }
        let msg = match read_server_msg(&mut listener, &mut buf, &mut read_buf, &mut stop_rx).await
        {
            Ok(m) => m,
            Err(err) => {
                if *stop_rx.borrow() {
                    break;
                }
                return Err(err);
            }
        };
        if let tun::ServerMsg::SessionOffer(session) = msg {
            let mut stop_rx2 = stop_rx.clone();
            match net::sock::backend_kind() {
                net::sock::BackendKind::Uring => {
                    net::sock::uring::spawn(async move {
                        if let Err(e) =
                            handle_session(ingress, key_id, secret, session, &mut stop_rx2).await
                        {
                            error!("tun handle_session failed: {e}");
                        }
                    });
                }
                _ => {
                    tokio::task::spawn_local(async move {
                        if let Err(e) =
                            handle_session(ingress, key_id, secret, session, &mut stop_rx2).await
                        {
                            error!("tun handle_session failed: {e}");
                        }
                    });
                }
            }
        }
    }
    Ok(())
}

async fn handle_session(
    ingress: SocketAddr,
    key_id: [u8; 8],
    secret: [u8; 32],
    session: [u8; 32],
    stop_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut agent_conn = tun::connect_agent(ingress).await?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let hmac = tun::compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        tun::Intent::Connect,
        Some(&session),
    );
    send_agent_hello(
        &mut agent_conn,
        tun::AgentHello {
            version: tun::VERSION,
            intent: tun::Intent::Connect,
            key_id,
            timestamp,
            hmac,
            session: Some(session),
        },
    )
    .await?;

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    let target = loop {
        match read_server_msg(&mut agent_conn, &mut buf, &mut read_buf, stop_rx).await? {
            tun::ServerMsg::TargetAddr(addr) => break addr,
            _ => continue,
        }
    };

    let mut target_conn = net::sock::Connection::connect(target).await?;
    // If the server already sent some tunneled bytes after TargetAddr in the same read,
    // forward them to the target before switching to passthrough.
    if !buf.is_empty() {
        let leftover = std::mem::take(&mut buf);
        let _ = target_conn.write_all(leftover).await?;
    }
    net::sock::passthrough_basic(&mut agent_conn, &mut target_conn).await?;
    Ok(())
}

async fn read_server_msg(
    conn: &mut net::sock::Connection,
    buf: &mut Vec<u8>,
    read_buf: &mut Vec<u8>,
    stop_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<tun::ServerMsg> {
    loop {
        if let Some((msg, consumed)) = tun::decode_server_msg(buf)? {
            buf.drain(..consumed);
            return Ok(msg);
        }

        tokio::select! {
            _ = stop_rx.changed() => {
                anyhow::bail!("stopped");
            }
            res = conn.read_chunk(std::mem::take(read_buf)) => {
                let (n, next) = res?;
                *read_buf = next;
                if n == 0 {
                    anyhow::bail!("server closed connection");
                }
                buf.extend_from_slice(&read_buf[..n]);
            }
        }
    }
}

async fn send_agent_hello(
    conn: &mut net::sock::Connection,
    hello: tun::AgentHello,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    tun::encode_agent_hello(&hello, &mut buf)?;
    conn.write_all(buf).await?;
    Ok(())
}

fn parse_args() -> anyhow::Result<SuiteConfig> {
    let mut duration = Duration::from_secs(DEFAULT_DURATION_SECS);
    let mut warmup = Duration::from_secs(DEFAULT_WARMUP_SECS);
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut pipeline = DEFAULT_PIPELINE;
    let mut payload = DEFAULT_PAYLOAD;
    let mut host = "test.local".to_string();
    let mut scenario = Scenario::Both;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--duration" => {
                let v = args.next().context("--duration requires a value")?;
                duration = Duration::from_secs(v.parse()?);
            }
            "--warmup" => {
                let v = args.next().context("--warmup requires a value")?;
                warmup = Duration::from_secs(v.parse()?);
            }
            "--concurrency" | "--connections" => {
                let v = args.next().context("--concurrency requires a value")?;
                concurrency = v.parse()?;
            }
            "--pipeline" => {
                let v = args.next().context("--pipeline requires a value")?;
                pipeline = v.parse()?;
            }
            "--payload" => {
                let v = args.next().context("--payload requires a value")?;
                payload = v.parse()?;
            }
            "--host" => {
                host = args.next().context("--host requires a value")?;
            }
            "--scenario" => {
                let v = args.next().context("--scenario requires a value")?;
                scenario = Scenario::parse(&v)?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(anyhow::anyhow!("unknown arg: {other}")),
        }
    }

    Ok(SuiteConfig {
        duration,
        warmup,
        concurrency,
        pipeline,
        payload,
        host,
        scenario,
    })
}

fn print_help() {
    println!("instance_tcp_test options:");
    println!("  --scenario <plain|tunnel|both>  (default both)");
    println!("  --host <hostname>               (default test.local)");
    println!("  --duration <secs>               (default {DEFAULT_DURATION_SECS})");
    println!("  --warmup <secs>                 (default {DEFAULT_WARMUP_SECS})");
    println!("  --concurrency <n>               (default {DEFAULT_CONCURRENCY})");
    println!("  --pipeline <n>                  (default {DEFAULT_PIPELINE})");
    println!("  --payload <bytes>               (default {DEFAULT_PAYLOAD})");
    println!();
    println!("what it checks:");
    println!("  - send/recv pairing: seq + embedded timestamp must match");
    println!("  - ordering: strict FIFO per TCP connection (pipelined requests)");
    println!("  - overhead latency: compares direct vs lure plain vs lure+tunnel");
}
