# tokio vs tokio-uring proxy benchmark (sock module)

Date: 2026-01-27

## Setup
- Workload: local TCP proxy (sock module) forwarding to a local echo backend
- Payload: 1024 bytes per request
- Concurrency: 32 client connections
- Duration: 15s (after 5s warmup)
- Backend selection: `LURE_IO_URING=0` vs `LURE_IO_URING=1` (requires `--features uring`)

## Methodology
- The proxy uses `sock::Listener` and `sock::Connection` for accept/connect and I/O.
- Each client performs a ping-pong loop: write payload, read payload.
- The proxy relays exactly `payload` bytes per direction per iteration to avoid
  partial-read bias and to keep the workload consistent across backends.
- Measurements include ops/sec, throughput, and latency percentiles.

## Commands
```
LURE_IO_URING=0 cargo run --bin bench_proxy --release -- --duration 15 --warmup 5 --concurrency 32 --payload 1024
LURE_IO_URING=1 cargo run --features uring --bin bench_proxy --release -- --duration 15 --warmup 5 --concurrency 32 --payload 1024
```

## Results

| Metric | tokio | tokio-uring | delta (uring vs tokio) |
| --- | ---:| ---:| ---:|
| ops/sec | 52,745.00 | 55,480.79 | +5.19% |
| throughput (MiB/s) | 103.02 | 108.36 | +5.18% |
| mean latency (us) | 606.48 | 576.56 | -4.93% |
| median latency (us) | 575.17 | 553.92 | -3.69% |
| p95 latency (us) | 859.22 | 741.11 | -13.75% |
| p99 latency (us) | 1004.50 | 882.42 | -12.15% |
| max latency (us) | 2462.53 | 5029.90 | +104.26% |
| samples | 791,286 | 832,369 | +5.19% |

## Analysis
- On this laptop and workload, **tokio-uring outperformed tokio** on throughput
  and p95/p99 latency, with modest improvements to mean/median latency.
- tokio-uring still had a significantly worse max latency, indicating higher tail
  spikes despite improved p95/p99.
- This suggests the io_uring backend now helps for this ping-pong workload on
  loopback, but tail stability is still a concern. Possible causes include:
  - The proxy loop is request/response (not streaming) and emphasizes per-IO
    latency over batching.
  - tokio-uring uses a different runtime and buffer model; the workload here is
    small-message and syscall-heavy.
  - The local echo server is blocking and may favor the tokio scheduler.

## Conclusion
For this benchmark, **tokio-uring is faster overall** but with worse max tail.
We should re-run with larger payloads, higher concurrency, and streaming copy
(full-duplex) to see if tail spikes smooth out while keeping throughput gains.
