#!/bin/bash
# Comprehensive benchmark comparing tokio vs epoll backends with nanosecond precision

set -e

DURATION=30
WARMUP=5
CONCURRENCY=32
PAYLOAD=1024

echo "======================================================================"
echo "Lure Backend Performance Comparison (Nanosecond Precision)"
echo "======================================================================"
echo ""
echo "Configuration:"
echo "  Duration: ${DURATION}s"
echo "  Warmup: ${WARMUP}s"
echo "  Concurrency: ${CONCURRENCY} connections"
echo "  Payload: ${PAYLOAD} bytes"
echo ""

# Build if needed
if [ ! -f "./target/release/bench_proxy" ]; then
    echo "Building benchmark binary..."
    cargo build --release --bin bench_proxy
    echo ""
fi

echo "======================================================================"
echo "Test 1: Tokio Backend (Baseline)"
echo "======================================================================"
./target/release/bench_proxy \
    --duration $DURATION \
    --warmup $WARMUP \
    --concurrency $CONCURRENCY \
    --payload $PAYLOAD
echo ""

echo "======================================================================"
echo "Test 2: Epoll Backend (HAProxy-Inspired Redesign)"
echo "======================================================================"
LURE_IO_EPOLL=1 ./target/release/bench_proxy \
    --duration $DURATION \
    --warmup $WARMUP \
    --concurrency $CONCURRENCY \
    --payload $PAYLOAD
echo ""

echo "======================================================================"
echo "Benchmark Complete"
echo "======================================================================"
echo ""
echo "NOTES:"
echo "- Latency measurement uses CLOCK_MONOTONIC for nanosecond precision"
echo "- Times are in microseconds (us)"
echo "- Each operation = write + read round-trip"
echo "- Compare p50, p99 latencies between backends"
echo "- Lower latency = better performance"
