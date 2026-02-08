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
use lure::sock::{self, BackendKind};

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

const DEFAULT_DURATION_SECS: u64 = 10;
const DEFAULT_WARMUP_SECS: u64 = 2;
const DEFAULT_CONCURRENCY: usize = 16;
const DEFAULT_PIPELINE: usize = 8;
const DEFAULT_PAYLOAD: usize = 1024;

const PROXY_BUF_SIZE: usize = 16 * 1024;

const FRAME_MAGIC: [u8; 4] = *b"LRTT";

#[derive(Clone, Copy, Debug)]
enum Mode {
    Direct,
    Proxy,
    Both,
}

impl Mode {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "direct" => Ok(Self::Direct),
            "proxy" => Ok(Self::Proxy),
            "both" => Ok(Self::Both),
            other => Err(anyhow::anyhow!(
                "invalid --mode {other} (expected direct|proxy|both)"
            )),
        }
    }
}

struct TestConfig {
    duration: Duration,
    warmup: Duration,
    concurrency: usize,
    pipeline: usize,
    payload: usize,
    mode: Mode,
}

// Per-op latency (ns), plus validation outcomes.
#[derive(Clone, Copy)]
struct OpSample {
    total_ns: u64,
    send_ns: u64,
    recv_ns: u64,
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
    stdev_ms: f64,
    send_mean_ms: f64,
    recv_mean_ms: f64,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cfg = parse_args()?;
    let backend = sock::backend_selection();

    println!("backend: {:?} ({})", backend.kind, backend.reason);
    println!(
        "config: mode={:?} duration={}s warmup={}s concurrency={} pipeline={} payload={}B",
        cfg.mode,
        cfg.duration.as_secs(),
        cfg.warmup.as_secs(),
        cfg.concurrency,
        cfg.pipeline,
        cfg.payload
    );

    if cfg.payload < 32 {
        anyhow::bail!("--payload must be >= 32 (need header + validation)");
    }
    if cfg.pipeline == 0 {
        anyhow::bail!("--pipeline must be > 0");
    }
    if cfg.concurrency == 0 {
        anyhow::bail!("--concurrency must be > 0");
    }

    let echo = FixedFrameEcho::start(cfg.payload)?;
    let proxy = ProxyServer::start(backend.kind, echo.addr, cfg.payload)?;

    let direct_addr = echo.addr;
    let proxy_addr = proxy.addr;

    let mut direct_result = None;
    let mut proxy_result = None;

    if cfg.warmup.as_secs() > 0 {
        match cfg.mode {
            Mode::Direct => {
                let _ = run_load(&cfg, direct_addr, false)?;
            }
            Mode::Proxy => {
                let _ = run_load(&cfg, proxy_addr, false)?;
            }
            Mode::Both => {
                let _ = run_load(&cfg, direct_addr, false)?;
                let _ = run_load(&cfg, proxy_addr, false)?;
            }
        }
    }

    match cfg.mode {
        Mode::Direct => {
            direct_result = Some(run_load(&cfg, direct_addr, true)?);
        }
        Mode::Proxy => {
            proxy_result = Some(run_load(&cfg, proxy_addr, true)?);
        }
        Mode::Both => {
            direct_result = Some(run_load(&cfg, direct_addr, true)?);
            proxy_result = Some(run_load(&cfg, proxy_addr, true)?);
        }
    }

    proxy.stop();
    echo.stop();

    if let Some(r) = &direct_result {
        println!();
        println!("direct:");
        report(r);
    }
    if let Some(r) = &proxy_result {
        println!();
        println!("proxy:");
        report(r);
    }
    if let (Some(d), Some(p)) = (&direct_result, &proxy_result) {
        println!();
        println!("overhead (proxy - direct):");
        report_overhead(d, p);
    }

    Ok(())
}

fn parse_args() -> anyhow::Result<TestConfig> {
    let mut duration = Duration::from_secs(DEFAULT_DURATION_SECS);
    let mut warmup = Duration::from_secs(DEFAULT_WARMUP_SECS);
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut pipeline = DEFAULT_PIPELINE;
    let mut payload = DEFAULT_PAYLOAD;
    let mut mode = Mode::Both;

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
            "--mode" => {
                let v = args.next().context("--mode requires a value")?;
                mode = Mode::parse(&v)?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(anyhow::anyhow!("unknown arg: {other}")),
        }
    }

    Ok(TestConfig {
        duration,
        warmup,
        concurrency,
        pipeline,
        payload,
        mode,
    })
}

fn print_help() {
    println!("tcp_test options:");
    println!("  --mode <direct|proxy|both>  (default both)");
    println!("  --duration <secs>           (default {DEFAULT_DURATION_SECS})");
    println!("  --warmup <secs>             (default {DEFAULT_WARMUP_SECS})");
    println!("  --concurrency <n>           (default {DEFAULT_CONCURRENCY})");
    println!("  --pipeline <n>              (default {DEFAULT_PIPELINE})");
    println!("  --payload <bytes>           (default {DEFAULT_PAYLOAD})");
    println!();
    println!("notes:");
    println!("  - Validates send/recv pairing and strict FIFO response order per-connection.");
    println!("  - Prints latency stats and (when mode=both) proxy RTT overhead vs direct.");
    println!("  - Backend selection follows Lure's socket backend env (e.g. LURE_IO_EPOLL=1).");
}

fn run_load(cfg: &TestConfig, addr: SocketAddr, record_samples: bool) -> anyhow::Result<RunResult> {
    let deadline = Instant::now() + cfg.duration;
    let (tx, rx) = std::sync::mpsc::channel();

    for _ in 0..cfg.concurrency {
        let tx = tx.clone();
        let payload = cfg.payload;
        let pipeline = cfg.pipeline;
        thread::spawn(move || {
            let r = client_worker(addr, payload, pipeline, deadline, record_samples);
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

struct Pending {
    seq: u64,
    send_ts_ns: u64,
    send_start_ns: u64,
    send_end_ns: u64,
}

fn client_worker(
    addr: SocketAddr,
    payload: usize,
    pipeline: usize,
    deadline: Instant,
    record_samples: bool,
) -> anyhow::Result<ThreadResult> {
    let mut stream = TcpStream::connect(addr)?;
    let _ = stream.set_nodelay(true);

    let mut seq = 0u64;
    let mut ops = 0u64;
    let mut samples = Vec::new();

    let mut write_buf = vec![0u8; payload];
    let mut read_buf = vec![0u8; payload];
    let mut pending: VecDeque<Pending> = VecDeque::with_capacity(pipeline + 1);

    loop {
        let now = Instant::now();
        if now >= deadline && pending.is_empty() {
            break;
        }

        // Send: fill up pipeline while we still have time budget.
        while pending.len() < pipeline && Instant::now() < deadline {
            let send_ts_ns = get_nanos();
            fill_frame(&mut write_buf, seq, send_ts_ns);

            let send_start_ns = get_nanos();
            stream.write_all(&write_buf)?;
            let send_end_ns = get_nanos();

            pending.push_back(Pending {
                seq,
                send_ts_ns,
                send_start_ns,
                send_end_ns,
            });
            seq = seq.wrapping_add(1);
        }

        // Receive: drain responses FIFO and validate.
        while !pending.is_empty() {
            let recv_start_ns = get_nanos();
            stream.read_exact(&mut read_buf)?;
            let recv_end_ns = get_nanos();

            let p = pending.pop_front().expect("checked non-empty");
            validate_frame(&read_buf, p.seq, p.send_ts_ns)
                .with_context(|| format!("frame validation failed (seq={})", p.seq))?;

            ops += 1;
            if record_samples {
                samples.push(OpSample {
                    total_ns: recv_end_ns.saturating_sub(p.send_start_ns),
                    send_ns: p.send_end_ns.saturating_sub(p.send_start_ns),
                    recv_ns: recv_end_ns.saturating_sub(recv_start_ns),
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

fn fill_frame(buf: &mut [u8], seq: u64, send_ts_ns: u64) {
    // Header:
    // 0..4 magic
    // 4..8 fnv64 header tag low32
    // 8..16 seq (be)
    // 16..24 send_ts_ns (be)
    // 24..32 body tag (be)
    buf[..4].copy_from_slice(&FRAME_MAGIC);

    let header_tag = (fnv64(&seq.to_be_bytes()) as u32).to_be_bytes();
    buf[4..8].copy_from_slice(&header_tag);
    buf[8..16].copy_from_slice(&seq.to_be_bytes());
    buf[16..24].copy_from_slice(&send_ts_ns.to_be_bytes());

    let body_tag = fnv64_with_seed(seq, send_ts_ns).to_be_bytes();
    buf[24..32].copy_from_slice(&body_tag);

    // Body: deterministic pattern derived from (seq, send_ts_ns).
    let seed = (seq as u8) ^ (send_ts_ns as u8) ^ 0x5a;
    for (i, b) in buf[32..].iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).rotate_left((i % 7) as u32);
    }
}

fn validate_frame(buf: &[u8], expect_seq: u64, expect_send_ts_ns: u64) -> anyhow::Result<()> {
    if buf.len() < 32 {
        anyhow::bail!("short frame: {} bytes", buf.len());
    }
    if buf[..4] != FRAME_MAGIC {
        anyhow::bail!("bad magic");
    }

    let mut tag_bytes = [0u8; 4];
    tag_bytes.copy_from_slice(&buf[4..8]);
    let got_header_tag = u32::from_be_bytes(tag_bytes);
    let expect_header_tag = fnv64(&expect_seq.to_be_bytes()) as u32;
    if got_header_tag != expect_header_tag {
        anyhow::bail!("bad header tag: got={got_header_tag} expect={expect_header_tag}");
    }

    let got_seq = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    if got_seq != expect_seq {
        anyhow::bail!("out-of-order: got seq={got_seq} expect seq={expect_seq}");
    }

    let got_send_ts_ns = u64::from_be_bytes(buf[16..24].try_into().unwrap());
    if got_send_ts_ns != expect_send_ts_ns {
        anyhow::bail!(
            "pair mismatch: got send_ts_ns={got_send_ts_ns} expect send_ts_ns={expect_send_ts_ns}"
        );
    }

    let got_body_tag = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    let expect_body_tag = fnv64_with_seed(expect_seq, expect_send_ts_ns);
    if got_body_tag != expect_body_tag {
        anyhow::bail!("bad body tag: got={got_body_tag} expect={expect_body_tag}");
    }

    // Verify body bytes.
    let seed = (expect_seq as u8) ^ (expect_send_ts_ns as u8) ^ 0x5a;
    for (i, b) in buf[32..].iter().enumerate() {
        let expect = seed.wrapping_add(i as u8).rotate_left((i % 7) as u32);
        if *b != expect {
            anyhow::bail!(
                "body mismatch at offset {}: got={} expect={}",
                32 + i,
                *b,
                expect
            );
        }
    }
    Ok(())
}

fn fnv64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn fnv64_with_seed(seq: u64, ts: u64) -> u64 {
    let mut tmp = [0u8; 16];
    tmp[..8].copy_from_slice(&seq.to_be_bytes());
    tmp[8..].copy_from_slice(&ts.to_be_bytes());
    fnv64(&tmp)
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
    println!("    stdev: {:.4}", s.stdev_ms);
    println!("  latency components (ms):");
    println!("    send avg: {:.4}", s.send_mean_ms);
    println!("    recv avg: {:.4}", s.recv_mean_ms);
    println!("    samples: {}", s.count);
}

fn report_overhead(d: &RunResult, p: &RunResult) {
    if d.samples.is_empty() || p.samples.is_empty() {
        println!("  (missing samples)");
        return;
    }
    let ds = latency_stats(&d.samples);
    let ps = latency_stats(&p.samples);

    println!("  p50_ms: {:.4}", ps.p50_ms - ds.p50_ms);
    println!("  p95_ms: {:.4}", ps.p95_ms - ds.p95_ms);
    println!("  p99_ms: {:.4}", ps.p99_ms - ds.p99_ms);
    println!("  mean_ms: {:.4}", ps.mean_ms - ds.mean_ms);
}

fn latency_stats(samples: &[OpSample]) -> LatencyStats {
    let count = samples.len();
    let mut ns: Vec<u64> = samples.iter().map(|s| s.total_ns).collect();
    ns.sort_unstable();

    let mut sum = 0f64;
    let mut sum_sq = 0f64;
    let mut send_sum = 0f64;
    let mut recv_sum = 0f64;
    for s in samples {
        let ms = s.total_ns as f64 / 1_000_000.0;
        let send_ms = s.send_ns as f64 / 1_000_000.0;
        let recv_ms = s.recv_ns as f64 / 1_000_000.0;
        sum += ms;
        sum_sq += ms * ms;
        send_sum += send_ms;
        recv_sum += recv_ms;
    }
    let mean_ms = sum / count as f64;
    let variance = mean_ms.mul_add(-mean_ms, sum_sq / count as f64);
    let stdev_ms = variance.max(0.0).sqrt();

    LatencyStats {
        count,
        mean_ms,
        p50_ms: percentile_ms(&ns, 50.0),
        p95_ms: percentile_ms(&ns, 95.0),
        p99_ms: percentile_ms(&ns, 99.0),
        max_ms: (*ns.last().unwrap_or(&0) as f64) / 1_000_000.0,
        stdev_ms,
        send_mean_ms: send_sum / count as f64,
        recv_mean_ms: recv_sum / count as f64,
    }
}

fn percentile_ms(sorted_ns: &[u64], pct: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * (sorted_ns.len() as f64 - 1.0)).round() as usize;
    sorted_ns[rank.min(sorted_ns.len() - 1)] as f64 / 1_000_000.0
}

struct FixedFrameEcho {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

impl FixedFrameEcho {
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
                        thread::spawn(move || echo_exact_loop(stream, frame_size));
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

fn echo_exact_loop(mut stream: TcpStream, frame_size: usize) {
    let mut buf = vec![0u8; frame_size];
    loop {
        if stream.read_exact(&mut buf).is_err() {
            break;
        }
        if stream.write_all(&buf).is_err() {
            break;
        }
    }
}

struct ProxyServer {
    addr: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    join: thread::JoinHandle<anyhow::Result<()>>,
}

impl ProxyServer {
    fn start(
        kind: BackendKind,
        backend_addr: SocketAddr,
        frame_size: usize,
    ) -> anyhow::Result<Self> {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let join = thread::spawn(move || match kind {
            BackendKind::Tokio => run_proxy_tokio(backend_addr, frame_size, addr_tx, stop_rx),
            BackendKind::Epoll => run_proxy_tokio(backend_addr, frame_size, addr_tx, stop_rx),
            BackendKind::Uring => run_proxy_uring(backend_addr, frame_size, addr_tx, stop_rx),
        });

        let addr = addr_rx.recv().context("failed to get proxy addr")?;
        Ok(Self {
            addr,
            stop: stop_tx,
            join,
        })
    }

    fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.join.join();
    }
}

fn run_proxy_tokio(
    backend_addr: SocketAddr,
    frame_size: usize,
    addr_tx: std::sync::mpsc::Sender<SocketAddr>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let listener = sock::LureListener::bind("127.0.0.1:0".parse()?).await?;
                let addr = listener.local_addr()?;
                let _ = addr_tx.send(addr);

                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        res = listener.accept() => {
                            let (client, _) = res?;
                            tokio::task::spawn_local(async move {
                                let _ = proxy_connection(client, backend_addr, frame_size).await;
                            });
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
            .await
    })
}

fn run_proxy_uring(
    backend_addr: SocketAddr,
    frame_size: usize,
    addr_tx: std::sync::mpsc::Sender<SocketAddr>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    net::sock::uring::start(async move {
        let listener = sock::LureListener::bind("127.0.0.1:0".parse()?).await?;
        let addr = listener.local_addr()?;
        let _ = addr_tx.send(addr);

        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                res = listener.accept() => {
                    let (client, _) = res?;
                    net::sock::uring::spawn(async move {
                        let _ = proxy_connection(client, backend_addr, frame_size).await;
                    });
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

async fn proxy_connection(
    mut client: sock::LureConnection,
    backend_addr: SocketAddr,
    frame_size: usize,
) -> io::Result<()> {
    let mut server = sock::LureConnection::connect(backend_addr).await?;
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    let mut c2s_buf = vec![0u8; PROXY_BUF_SIZE];
    let mut s2c_buf = vec![0u8; PROXY_BUF_SIZE];

    loop {
        match relay_exact(&mut client, &mut server, c2s_buf, frame_size).await {
            Ok(buf) => c2s_buf = buf,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
        match relay_exact(&mut server, &mut client, s2c_buf, frame_size).await {
            Ok(buf) => s2c_buf = buf,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

async fn relay_exact(
    from: &mut sock::LureConnection,
    to: &mut sock::LureConnection,
    mut buf: Vec<u8>,
    mut remaining: usize,
) -> io::Result<Vec<u8>> {
    while remaining > 0 {
        let read_len = remaining.min(PROXY_BUF_SIZE);
        if buf.len() != read_len {
            buf.resize(read_len, 0);
        }
        let (n, mut out) = from.read_chunk(buf).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
        }
        out.truncate(n);
        out = to.write_all(out).await?;
        remaining = remaining.saturating_sub(n);
        out.clear();
        if out.capacity() < PROXY_BUF_SIZE {
            out.reserve_exact(PROXY_BUF_SIZE - out.capacity());
        }
        buf = out;
    }
    Ok(buf)
}
