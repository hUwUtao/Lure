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

const DEFAULT_DURATION_SECS: u64 = 15;
const DEFAULT_WARMUP_SECS: u64 = 5;
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_PAYLOAD: usize = 1024;
const PROXY_BUF_SIZE: usize = 16 * 1024;

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
    latencies_ns: Vec<u64>,
}

struct LatencyStats {
    count: usize,
    mean_us: f64,
    median_us: f64,
    p95_us: f64,
    p99_us: f64,
    max_us: f64,
    stdev_us: f64,
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
    let mut latencies_ns = Vec::new();

    for thread_result in rx {
        total_ops += thread_result.total_ops;
        total_bytes += thread_result.total_bytes;
        if record_latencies {
            latencies_ns.extend(thread_result.latencies_ns);
        }
    }

    Ok(BenchResult {
        duration: start.elapsed(),
        total_ops,
        total_bytes,
        latencies_ns,
    })
}

struct ThreadResult {
    total_ops: u64,
    total_bytes: u64,
    latencies_ns: Vec<u64>,
}

fn client_worker(
    proxy_addr: SocketAddr,
    payload: usize,
    deadline: Instant,
    record_latencies: bool,
) -> ThreadResult {
    let mut total_ops = 0u64;
    let mut latencies_ns = Vec::new();

    let mut stream = match TcpStream::connect(proxy_addr) {
        Ok(stream) => stream,
        Err(_) => {
            return ThreadResult {
                total_ops: 0,
                total_bytes: 0,
                latencies_ns,
            }
        }
    };
    let _ = stream.set_nodelay(true);

    let write_buf = vec![0u8; payload];
    let mut read_buf = vec![0u8; payload];

    while Instant::now() < deadline {
        let start = Instant::now();
        if stream.write_all(&write_buf).is_err() {
            break;
        }
        if stream.read_exact(&mut read_buf).is_err() {
            break;
        }
        total_ops += 1;
        if record_latencies {
            latencies_ns.push(start.elapsed().as_nanos() as u64);
        }
    }

    ThreadResult {
        total_ops,
        total_bytes: total_ops * payload as u64 * 2,
        latencies_ns,
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

    if result.latencies_ns.is_empty() {
        println!("  latency: (none)");
        return;
    }

    let mut latencies = result.latencies_ns.clone();
    if let Some(stats) = latency_stats(&mut latencies) {
        println!("  latency (us):");
        println!("    mean: {:.2}", stats.mean_us);
        println!("    median: {:.2}", stats.median_us);
        println!("    p95: {:.2}", stats.p95_us);
        println!("    p99: {:.2}", stats.p99_us);
        println!("    max: {:.2}", stats.max_us);
        println!("    stdev: {:.2}", stats.stdev_us);
        println!("    samples: {}", stats.count);
    }
}

fn latency_stats(latencies_ns: &mut [u64]) -> Option<LatencyStats> {
    if latencies_ns.is_empty() {
        return None;
    }

    latencies_ns.sort_unstable();
    let count = latencies_ns.len();
    let mut sum = 0f64;
    let mut sum_sq = 0f64;

    for &value in latencies_ns.iter() {
        let us = value as f64 / 1_000.0;
        sum += us;
        sum_sq += us * us;
    }

    let mean_us = sum / count as f64;
    let variance = (sum_sq / count as f64) - (mean_us * mean_us);
    let stdev_us = variance.max(0.0).sqrt();
    let median_us = percentile_us(latencies_ns, 50.0);
    let p95_us = percentile_us(latencies_ns, 95.0);
    let p99_us = percentile_us(latencies_ns, 99.0);
    let max_us = *latencies_ns.last().unwrap() as f64 / 1_000.0;

    Some(LatencyStats {
        count,
        mean_us,
        median_us,
        p95_us,
        p99_us,
        max_us,
        stdev_us,
    })
}

fn percentile_us(latencies_ns: &[u64], pct: f64) -> f64 {
    if latencies_ns.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * (latencies_ns.len() as f64 - 1.0)).round() as usize;
    latencies_ns[rank.min(latencies_ns.len() - 1)] as f64 / 1_000.0
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
                let listener = sock::Listener::bind("127.0.0.1:0".parse()?).await?;
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
    tokio_uring::start(async move {
        let listener = sock::Listener::bind("127.0.0.1:0".parse()?).await?;
        let addr = listener.local_addr()?;
        let _ = addr_tx.send(addr);

        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                res = listener.accept() => {
                    let (client, _) = res?;
                    tokio_uring::spawn(async move {
                        let _ = proxy_connection(client, backend_addr, payload).await;
                    });
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

async fn proxy_connection(
    mut client: sock::Connection,
    backend_addr: SocketAddr,
    payload: usize,
) -> io::Result<()> {
    let mut server = sock::Connection::connect(backend_addr).await?;
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
    from: &mut sock::Connection,
    to: &mut sock::Connection,
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
