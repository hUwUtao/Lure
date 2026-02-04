use std::{
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

// High-precision nanosecond timer using CLOCK_MONOTONIC
fn get_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

const DEFAULT_DURATION_SECS: u64 = 15;
const DEFAULT_WARMUP_SECS: u64 = 5;
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_PAYLOAD: usize = 1024;
const PROXY_BUF_SIZE: usize = 16 * 1024;

// Nanosecond precision timestamps for each operation
struct TimestampedLatency {
    total_ns: u64,      // Total round-trip latency (send_start to recv_end)
    send_ns: u64,       // Send phase latency (time to write)
    recv_ns: u64,       // Receive phase latency (time to read response)
}

// Request with embedded timestamp for validation
#[repr(C)]
struct PipelinedRequest {
    seq_num: u64,       // Sequence number for matching
    send_ts_ns: u64,    // Send timestamp (nanoseconds)
    padding: [u8; 1008], // Pad to payload size
}

struct BenchConfig {
    duration: Duration,
    warmup: Duration,
    concurrency: usize,
    payload: usize,
}

struct BenchResult {
    duration: Duration,
    total_ops: u64,
    total_bytes: u64,
    latencies: Vec<TimestampedLatency>,
}

struct LatencyStats {
    count: usize,
    mean_ms: f64,
    median_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    stdev_ms: f64,
    send_mean_ms: f64,
    recv_mean_ms: f64,
}

fn main() -> anyhow::Result<()> {
    let config = parse_args()?;
    let backend = sock::backend_selection();

    println!("backend: {:?} ({})", backend.kind, backend.reason);
    println!(
        "config: duration={}s warmup={}s concurrency={} payload={}B",
        config.duration.as_secs(),
        config.warmup.as_secs(),
        config.concurrency,
        config.payload
    );

    let echo = EchoServer::start()?;
    let proxy = ProxyServer::start(backend.kind, echo.addr, config.payload)?;

    if config.warmup.as_secs() > 0 {
        let _ = run_client_load(&config, proxy.addr, false)?;
    }

    let result = run_client_load(&config, proxy.addr, true)?;

    proxy.stop();
    echo.stop();

    report(&result);

    Ok(())
}

fn parse_args() -> anyhow::Result<BenchConfig> {
    let mut duration = Duration::from_secs(DEFAULT_DURATION_SECS);
    let mut warmup = Duration::from_secs(DEFAULT_WARMUP_SECS);
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut payload = DEFAULT_PAYLOAD;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--duration" => {
                let value = args.next().context("--duration requires a value")?;
                duration = Duration::from_secs(value.parse()?);
            }
            "--warmup" => {
                let value = args.next().context("--warmup requires a value")?;
                warmup = Duration::from_secs(value.parse()?);
            }
            "--concurrency" | "--connections" => {
                let value = args.next().context("--concurrency requires a value")?;
                concurrency = value.parse()?;
            }
            "--payload" => {
                let value = args.next().context("--payload requires a value")?;
                payload = value.parse()?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(anyhow::anyhow!("unknown arg: {other}")),
        }
    }

    if payload == 0 {
        return Err(anyhow::anyhow!("payload must be > 0"));
    }
    if concurrency == 0 {
        return Err(anyhow::anyhow!("concurrency must be > 0"));
    }

    Ok(BenchConfig {
        duration,
        warmup,
        concurrency,
        payload,
    })
}

fn print_help() {
    println!("bench_proxy options:");
    println!("  --duration <secs>     (default {DEFAULT_DURATION_SECS})");
    println!("  --warmup <secs>       (default {DEFAULT_WARMUP_SECS})");
    println!("  --concurrency <n>      (default {DEFAULT_CONCURRENCY})");
    println!("  --payload <bytes>      (default {DEFAULT_PAYLOAD})");
}

fn run_client_load(
    config: &BenchConfig,
    proxy_addr: SocketAddr,
    record_latencies: bool,
) -> anyhow::Result<BenchResult> {
    let deadline = Instant::now() + config.duration;
    let (tx, rx) = std::sync::mpsc::channel();

    for _ in 0..config.concurrency {
        let tx = tx.clone();
        let proxy_addr = proxy_addr;
        let payload = config.payload;
        thread::spawn(move || {
            let result = client_worker(proxy_addr, payload, deadline, record_latencies);
            let _ = tx.send(result);
        });
    }
    drop(tx);

    let start = Instant::now();
    let mut total_ops = 0u64;
    let mut total_bytes = 0u64;
    let mut latencies = Vec::new();

    for thread_result in rx {
        total_ops += thread_result.total_ops;
        total_bytes += thread_result.total_bytes;
        if record_latencies {
            latencies.extend(thread_result.latencies);
        }
    }

    Ok(BenchResult {
        duration: start.elapsed(),
        total_ops,
        total_bytes,
        latencies,
    })
}

struct ThreadResult {
    total_ops: u64,
    total_bytes: u64,
    latencies: Vec<TimestampedLatency>,
}

fn client_worker(
    proxy_addr: SocketAddr,
    payload: usize,
    deadline: Instant,
    record_latencies: bool,
) -> ThreadResult {
    let mut total_ops = 0u64;
    let mut latencies = Vec::new();

    let mut stream = match TcpStream::connect(proxy_addr) {
        Ok(stream) => stream,
        Err(_) => {
            return ThreadResult {
                total_ops: 0,
                total_bytes: 0,
                latencies,
            }
        }
    };
    let _ = stream.set_nodelay(true);

    // Pipelined I/O: send multiple requests, then drain responses
    // This measures send and receive latency separately
    const PIPELINE_DEPTH: usize = 8;
    let mut write_buf = vec![0u8; payload];
    let mut read_buf = vec![0u8; payload];
    let mut pending_timestamps = Vec::new(); // vec of send_timestamp

    // Pre-fill write buffer with data
    for i in 0..payload {
        write_buf[i] = (i % 256) as u8;
    }

    loop {
        let now = Instant::now();
        if now >= deadline && pending_timestamps.is_empty() {
            break;
        }

        // Send phase: queue up to PIPELINE_DEPTH requests in parallel
        while pending_timestamps.len() < PIPELINE_DEPTH && now < deadline {
            let send_start_ns = get_nanos();
            match stream.write_all(&write_buf) {
                Ok(_) => {
                    let send_end_ns = get_nanos();
                    pending_timestamps.push((send_start_ns, send_end_ns));
                }
                Err(_) => {
                    return ThreadResult {
                        total_ops,
                        total_bytes: total_ops * payload as u64 * 2,
                        latencies,
                    };
                }
            }
        }

        // Receive phase: drain responses in FIFO order
        while !pending_timestamps.is_empty() {
            let recv_start_ns = get_nanos();
            match stream.read_exact(&mut read_buf) {
                Ok(_) => {
                    let recv_end_ns = get_nanos();
                    let (send_start_ns, send_end_ns) = pending_timestamps.remove(0);

                    let send_ns = send_end_ns - send_start_ns;
                    let recv_ns = recv_end_ns - recv_start_ns;
                    let total_ns = recv_end_ns - send_start_ns;

                    total_ops += 1;
                    if record_latencies {
                        latencies.push(TimestampedLatency {
                            total_ns,
                            send_ns,
                            recv_ns,
                        });
                    }
                }
                Err(_) => {
                    return ThreadResult {
                        total_ops,
                        total_bytes: total_ops * payload as u64 * 2,
                        latencies,
                    };
                }
            }
        }
    }

    ThreadResult {
        total_ops,
        total_bytes: total_ops * payload as u64 * 2,
        latencies,
    }
}

fn report(result: &BenchResult) {
    let duration_secs = result.duration.as_secs_f64().max(0.001);
    let ops_per_sec = result.total_ops as f64 / duration_secs;
    let mib_per_sec = result.total_bytes as f64 / (1024.0 * 1024.0) / duration_secs;

    println!("results:");
    println!("  ops: {}", result.total_ops);
    println!("  bytes: {}", result.total_bytes);
    println!("  duration: {:.3}s", duration_secs);
    println!("  ops/sec: {:.2}", ops_per_sec);
    println!("  throughput: {:.2} MiB/s", mib_per_sec);

    if result.latencies.is_empty() {
        println!("  latency: (none)");
        return;
    }

    if let Some(stats) = latency_stats(&result.latencies) {
        println!("  latency (ms):");
        println!("    mean: {:.4}", stats.mean_ms);
        println!("    median (p50): {:.4}", stats.p50_ms);
        println!("    p95: {:.4}", stats.p95_ms);
        println!("    p99: {:.4}", stats.p99_ms);
        println!("    max: {:.4}", stats.max_ms);
        println!("    stdev: {:.4}", stats.stdev_ms);
        println!("  latency components (ms):");
        println!("    send avg: {:.4}", stats.send_mean_ms);
        println!("    recv avg: {:.4}", stats.recv_mean_ms);
        println!("    samples: {}", stats.count);
    }
}

fn latency_stats(latencies: &[TimestampedLatency]) -> Option<LatencyStats> {
    if latencies.is_empty() {
        return None;
    }

    let count = latencies.len();

    // Extract total latencies for percentile calculation (in ns)
    let mut total_latencies: Vec<u64> = latencies.iter().map(|l| l.total_ns).collect();
    total_latencies.sort_unstable();

    let mut total_sum = 0f64;
    let mut total_sum_sq = 0f64;
    let mut send_sum = 0f64;
    let mut recv_sum = 0f64;

    for lat in latencies.iter() {
        let total_ms = lat.total_ns as f64 / 1_000_000.0;
        let send_ms = lat.send_ns as f64 / 1_000_000.0;
        let recv_ms = lat.recv_ns as f64 / 1_000_000.0;

        total_sum += total_ms;
        total_sum_sq += total_ms * total_ms;
        send_sum += send_ms;
        recv_sum += recv_ms;
    }

    let mean_ms = total_sum / count as f64;
    let variance = (total_sum_sq / count as f64) - (mean_ms * mean_ms);
    let stdev_ms = variance.max(0.0).sqrt();
    let send_mean_ms = send_sum / count as f64;
    let recv_mean_ms = recv_sum / count as f64;

    let p50_ms = percentile_ms(&total_latencies, 50.0);
    let p95_ms = percentile_ms(&total_latencies, 95.0);
    let p99_ms = percentile_ms(&total_latencies, 99.0);
    let max_ms = *total_latencies.last().unwrap() as f64 / 1_000_000.0;

    Some(LatencyStats {
        count,
        mean_ms,
        median_ms: p50_ms,
        p50_ms,
        p95_ms,
        p99_ms,
        max_ms,
        stdev_ms,
        send_mean_ms,
        recv_mean_ms,
    })
}

fn percentile_ms(latencies_ns: &[u64], pct: f64) -> f64 {
    if latencies_ns.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * (latencies_ns.len() as f64 - 1.0)).round() as usize;
    latencies_ns[rank.min(latencies_ns.len() - 1)] as f64 / 1_000_000.0
}

struct EchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

impl EchoServer {
    fn start() -> io::Result<Self> {
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
                        thread::spawn(move || echo_loop(stream));
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

fn echo_loop(mut stream: TcpStream) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if stream.write_all(&buf[..n]).is_err() {
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
    fn start(kind: BackendKind, backend_addr: SocketAddr, payload: usize) -> anyhow::Result<Self> {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

        let join = thread::spawn(move || match kind {
            BackendKind::Tokio => run_proxy_tokio(backend_addr, payload, addr_tx, stop_rx),
            BackendKind::Epoll => run_proxy_tokio(backend_addr, payload, addr_tx, stop_rx),
            BackendKind::Uring => run_proxy_uring(backend_addr, payload, addr_tx, stop_rx),
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
    payload: usize,
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
                                let _ = proxy_connection(client, backend_addr, payload).await;
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
    payload: usize,
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
                        let _ = proxy_connection(client, backend_addr, payload).await;
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
    payload: usize,
) -> io::Result<()> {
    let mut server = sock::LureConnection::connect(backend_addr).await?;
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    let mut c2s_buf = vec![0u8; PROXY_BUF_SIZE];
    let mut s2c_buf = vec![0u8; PROXY_BUF_SIZE];

    loop {
        match relay_exact(&mut client, &mut server, c2s_buf, payload).await {
            Ok(buf) => c2s_buf = buf,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
        match relay_exact(&mut server, &mut client, s2c_buf, payload).await {
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
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed",
            ));
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
