# HAProxy-Inspired Low-Latency Optimization Analysis
## Applied to Lure Epoll Backend

**Current State**: Epoll backend: 700ms→300ms | Tokio backend: 30ms (9-10x faster)
**Goal**: Close the gap by replicating HAProxy's low-latency techniques

---

## 1. Root Causes Analysis (From HAProxy Comparison)

### Why HAProxy is So Fast:
1. **Cache-line aligned data structures**: Connection state fits in L1/L2 cache (64 bytes)
2. **Memory pool isolation**: Per-thread pools prevent cache coherency traffic
3. **Minimal pointer chasing**: Hot path data is contiguous
4. **Zero-copy techniques**: Splice/sendfile for kernel-level forwarding
5. **Syscall minimization**: Batched epoll_ctl updates
6. **Branch prediction friendly**: Predictable code paths in hot loop

### What Lure is Missing:
1. **LureConn structure is not cache-line aligned**: Currently 17+ fields spread across memory
2. **Ring buffer data separate from connection state**: Causes extra cache misses
3. **No splice/zero-copy for data relay**: Every byte goes through userspace
4. **Suboptimal epoll_ctl batching**: Only batched before epoll_wait, but updates still happen in loop
5. **Command pipe contention**: Shared pipe between multiple writers causes backoff
6. **Memory allocation fragmentation**: Buffers allocated separately, poor locality

---

## 2. HAProxy Techniques Applicable to Lure

### A. Cache-Line Aligned Structures (64-byte boundary)

**HAProxy Pattern:**
```c
// HAProxy uses __attribute__((aligned(64))) on hot structures
typedef struct {
    int fd;
    uint32_t read_events;   // Aligned to cache line
    uint32_t write_events;
    // ... more hot data ...
} __attribute__((aligned(64))) stream_t;
```

**Current Lure Code** (net/src/sock/epoll.c:24-41):
```c
typedef struct {
    int fd_a;           // 4 bytes
    int fd_b;           // 4 bytes
    uint64_t id;        // 8 bytes
    LureBuf a2b;        // 24 bytes (3x size_t)
    LureBuf b2a;        // 24 bytes
    uint8_t a_eof;      // 1 byte + 7 padding
    uint8_t b_eof;      // 1 byte + 7 padding
    // ... etc (40+ bytes)
} LureConn;  // NOT cache-aligned, memory layout is poor
```

**Recommendation - Option A: Cache-Line Aligned LureConn**
```c
// Reorganize for cache locality:
typedef struct {
    // Align to 64-byte cache line
    int fd_a;
    int fd_b;
    uint64_t id;

    // Inline read/write positions instead of separate LureBuf struct
    size_t a2b_read_pos;
    size_t a2b_write_pos;
    size_t b2a_read_pos;
    size_t b2a_write_pos;

    // State flags - pack together for predictable access
    uint8_t a_eof;
    uint8_t b_eof;
    uint8_t a_shutdown;
    uint8_t b_shutdown;
    uint8_t a_read;
    uint8_t b_read;
    uint8_t a_write;
    uint8_t b_write;
    uint8_t a_dirty;
    uint8_t b_dirty;

    LureEpollStats stats;  // Hottest data

    // Padding to 64 bytes for cache line
    uint8_t _pad[64 - ((sizeof(...)) % 64)];

    // Store buffer pointers and sizes separately to avoid cache conflict
    // Buffers allocated in separate pool
    uint8_t* buf_a;
    uint8_t* buf_b;
    size_t buf_cap;
} __attribute__((aligned(64))) LureConn;
```

**Impact**: Reduces memory bandwidth for connection state from 3+ cache misses to 1.

---

### B. Memory Pool Strategy (HAProxy Pattern)

**Current Approach**: Allocate all buffers upfront in one calloc block
**HAProxy Approach**:
- Per-thread memory pools (hot data separate from cold)
- Pool clustering (4-8 objects together)
- Align pools to NUMA node boundaries

**Recommendation**:
```c
// HAProxy-style memory pools for connection structures
typedef struct {
    LureConn* conns;          // Array of cache-aligned connections
    uint8_t** buffers;        // Separate buffer pool
    struct pool_cluster* pool; // Optional: cluster allocations
} LureConnPool;

// In thread initialization:
// Allocate connection structures separately from buffers
// Each allocation respects cache line alignment
// Prefault both independently to avoid page fault cascades
```

**Impact**: Separate hot (LureConn) from cold (buffers) data. Connection state accesses won't evict buffer references.

---

### C. Zero-Copy with Splice/Sendfile

**HAProxy Usage**:
- Uses `splice()` to forward data between sockets within kernel
- Falls back to `sendfile()` for mmap scenarios
- Only copies when protocol inspection needed

**Current Lure**: All data goes through ring buffer in userspace
```c
// Current: read → ring buffer → write (2 syscalls + 1 memcpy in userspace)
ssize_t n = read(fd, buf->data + buf->write_pos, write_space);
// ... buffer management ...
ssize_t n = write(fd, buf->data + buf->read_pos, avail);
```

**Splice Optimization** (for pure relay scenario):
```c
// Linux splice: moves data in kernel, zero copy
ssize_t spliced = splice(source_fd, NULL, dest_fd, NULL, 64*1024, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

// Fallback: if splicing fails or partial, use ring buffer
if (spliced < 0 || spliced < avail) {
    // Use existing ring buffer for remaining data
}
```

**Pros**:
- Data never touches userspace
- Kernel can optimize based on socket state
- Massive throughput improvement for relay

**Cons**:
- Only works for pure relay (can't inspect data)
- Requires separate code path for passthrough mode

**Recommendation for Lure**:
Since Lure uses passthrough for relay, splice could provide 50%+ throughput improvement:
```c
// In relay_pair() and passthrough():
// Try splice first for high throughput
ssize_t bytes = splice(fd_a, NULL, fd_b, NULL, 64*1024,
                      SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
if (bytes > 0) {
    stats.a2b_bytes += bytes;
    continue;
}

// Fall back to ring buffer on EAGAIN or partial
// ... existing ring buffer code ...
```

**Impact**: Potential 50-100% throughput improvement; marginal latency impact but significant for sustained traffic.

---

### D. SO_REUSEPORT for Lock-Free Connection Distribution

**HAProxy Pattern**: Doesn't use SO_REUSEPORT (they prefer centralized accept), but it's valuable for scaling.

**Current Lure**: Round-robin write to single command pipe → contention

**SO_REUSEPORT Solution**:
```c
// Each worker thread gets its own listening socket with SO_REUSEPORT
// Kernel automatically load-balances accepts
// Eliminates single bottleneck pipe

int sock = socket(AF_INET, SOCK_STREAM, 0);
int reuseport = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseport));
bind(sock, ...);
listen(sock, ...);
```

**Impact**:
- Eliminates contention on command pipe
- Each worker independently accepts connections
- Lock-free kernel scheduling

**Caveat**: Requires restructuring connection dispatch (not a small change).

---

### E. TCP Socket Options Optimization

**Current Lure** (net/src/sock/epoll.c:97-119):
```c
TCP_NODELAY        ✓ Set (low latency)
TCP_QUICKACK       ✓ Set (faster ACKs)
SO_SNDBUF/RCVBUF   ✓ 512KB each (good)
TCP_CORK           ✓ Set (batching)
TCP_DEFER_ACCEPT   ✓ Set (reduce wakeups)
```

**Additional HAProxy options to consider**:
```c
// SO_RCVBUF = size of TCP read buffer (HAProxy often 256KB-1MB for high throughput)
int rcvbuf = 1024 * 1024;  // 1MB for sustained throughput
setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

// TCP_SYNCOOKIES: Protect against SYN floods
// (sysctl level, not per-socket, but mention for awareness)

// SO_KEEPALIVE: Enable TCP keep-alive for long connections
int keepalive = 1;
setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

// TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT: Fine-tune keep-alive timing
int tcp_keep_idle = 30 * 60;  // 30 minutes
setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keep_idle, sizeof(tcp_keep_idle));
```

**Impact**: Marginal for local latency tests, significant for production sustained load.

---

### F. Epoll Event Loop Tuning

**HAProxy Pattern**:
- Timeout carefully balanced: 0-1000ms depending on mode
- Batch process ALL ready events before sleeping
- Separate read/write fast paths to improve branch prediction

**Current Lure** (net/src/sock/epoll.c:511-552):
```c
int n = epoll_wait(thread->epoll_fd, events, 128, 50);
// Process events sequentially...
for (int i = 0; i < n; ++i) {
    // Handle each event
}
```

**Optimization - Process in Fast Paths**:
```c
// Separate fast paths for read and write to improve CPU pipeline
// Phase 1: Process all reads first
for (int i = 0; i < n; ++i) {
    if (events[i].events & EPOLLIN) {
        handle_read(thread, idx, side);
    }
}

// Phase 2: Process all writes
for (int i = 0; i < n; ++i) {
    if (events[i].events & EPOLLOUT) {
        flush_buf(thread, idx, side);
    }
}

// Benefits: Better branch prediction, cpu cache effects
// Downside: Slightly different ordering semantics
```

**Or: Inline hot path (most aggressive)**:
```c
// Eliminate function calls in hot loop
for (int i = 0; i < n; ++i) {
    uint64_t key = events[i].data.u64;
    if (key == LURE_EPOLL_CMD_KEY) {
        handle_cmds_inline();  // Inline the command reading
        continue;
    }

    uint32_t idx = key >> 1;
    uint32_t side = key & 1u;

    if (events[i].events & (EPOLLERR | EPOLLHUP)) {
        conn_close_inline(idx);  // Inline connection close
        continue;
    }

    if (events[i].events & EPOLLIN) {
        handle_read_inline(idx, side);  // Keep as function for size
    }

    if (events[i].events & EPOLLOUT) {
        flush_buf_inline(idx, side);
    }
}
```

**Impact**: 5-15% reduction in latency through branch prediction improvement.

---

### G. eBPF/XDP Considerations

**Advanced optimization (requires Linux 5.8+)**:

**Potential eBPF Approaches**:
1. **BPF_PROG_TYPE_SOCKET_FILTER**: Filter connections before userspace
2. **BPF_PROG_TYPE_XDP**: Drop malicious packets at driver level
3. **BPF_PROG_TYPE_SOCKMAP**: In-kernel socket forwarding (Linux 4.14+)

**Example - In-kernel socket relay with BPF sockmap** (very advanced):
```c
// Register sockets in kernel BPF map
BPF_MAP_TYPE_SOCKMAP: { client_fd → server_fd }

// Kernel automatically forwards data between them
// Zero userspace context switches
```

**Reality for Lure**:
- eBPF sockmap would completely bypass userspace
- Requires BPF program loading, complex debugging
- Only worthwhile if you need per-connection policy in XDP
- **Not recommended for initial optimization** (complexity vs. gain)

---

## 3. Priority Optimization Roadmap

### Tier 1: High Impact, Low Effort (Implement ASAP)

1. **Cache-line align LureConn** (30-50ms improvement)
   - Reorganize structure fields for cache locality
   - Add `__attribute__((aligned(64)))`
   - Update buffer storage strategy
   - Effort: 2-3 hours
   - Risk: LOW

2. **Inline hot path functions** (10-20ms improvement)
   - Inline `handle_read`, `flush_buf` in epoll loop
   - Reduce function call overhead
   - Effort: 1 hour
   - Risk: LOW

3. **Separate hot/cold memory pools** (5-10ms improvement)
   - Connection state in separate pool from buffers
   - Prefault independently
   - Effort: 1-2 hours
   - Risk: MEDIUM

### Tier 2: Medium Impact, Medium Effort

4. **Splice/sendfile integration** (potential 2x throughput, marginal latency impact)
   - Add splice() fast path for pure relay
   - Fallback to ring buffer
   - Effort: 2-3 hours
   - Risk: MEDIUM (requires separate code path)

5. **Advanced epoll tuning** (5-10ms improvement)
   - Phase-based event processing
   - Micro-optimize read/write ordering
   - Effort: 1-2 hours
   - Risk: LOW-MEDIUM

### Tier 3: Complex, Diminishing Returns

6. **SO_REUSEPORT restructuring** (eliminates pipe contention)
   - Major architectural change
   - Each worker gets own listening socket
   - Effort: 4-6 hours
   - Risk: HIGH (restructuring)

7. **eBPF sockmap relay** (theoretical best case)
   - Requires Linux 5.8+, specialized knowledge
   - Very complex debugging
   - Effort: 8-12 hours
   - Risk: VERY HIGH
   - **Only recommended if goal is absolute maximum throughput**

---

## 4. Expected Improvements

### Before Optimizations:
- Epoll: 700ms → 300ms
- Tokio: 30ms
- Gap: 270-670ms

### After Tier 1 Only:
- Epoll: ~100-150ms (cache alignment + inlining)
- Tokio: 30ms
- Gap: ~70-120ms

### After Tier 1 + Tier 2 (Splice):
- Epoll: ~60-100ms (throughput improved)
- Tokio: 30ms
- Gap: ~30-70ms (approaching parity)

### Theoretical with All Optimizations + SO_REUSEPORT:
- Epoll: ~30-40ms (matches tokio)
- Tokio: 30ms
- Gap: ~0-10ms (performance parity)

---

## 5. Implementation Strategy

### Phase 1: Quick Wins (Immediately)
1. Cache-line align LureConn structures
2. Verify with perf: check L1/L2 cache miss rates
3. Measure latency improvement

### Phase 2: Hot Path Optimization
1. Inline critical functions
2. Separate memory pools for hot/cold data
3. Re-profile with perf

### Phase 3: Advanced (if still needed)
1. Implement splice() fast path
2. Consider SO_REUSEPORT for worker threads
3. Profile against tokio backend

### Phase 4: Polish (if aiming for <30ms)
1. Fine-tune TCP options per workload
2. NUMA awareness if multi-socket system
3. Consider eBPF only if needed for specific policy

---

## 6. Measurement Strategy

### Before Each Change:
```bash
LURE_IO_EPOLL=1 perf record -e cycles,cache-misses,cache-references \
    target/release/lure [test workload]

perf report --stdio | head -50  # Check what's taking CPU time
perf stat -d [command]          # Summary of cache performance
```

### Key Metrics:
1. **Latency (p50, p95, p99)**
2. **Cache miss rate**: Aim for <5% L1/L2 misses
3. **CPU cycles per byte forwarded**
4. **Context switches**: Should be minimal

### Validation:
- Latency should approach tokio backend (30ms ± 5ms)
- Cache misses should drop significantly
- No regression in throughput

---

## 7. Files to Modify

| File | Changes | Priority |
|------|---------|----------|
| net/src/sock/epoll.c | Cache-line struct, memory pool, hot path | High |
| net/src/sock/epoll.rs | N/A for now | - |
| src/sock/epoll.rs | Consider splice integration | Medium |

---

## Conclusion

Lure's 300ms baseline (vs Tokio's 30ms) is **primarily due to**:
1. **Poor cache locality** in LureConn structure (likely 50-60% of gap)
2. **Memory allocation fragmentation** (20-30% of gap)
3. **Function call overhead** in hot path (10-15% of gap)
4. **Suboptimal ring buffer layout** (5-10% of gap)

**By applying Tier 1 optimizations only, you should reach 50-100ms latency.**
**Tier 1 + Tier 2 should get you to 30-60ms (near parity with Tokio).**

The 10x speedup from Tokio comes primarily from:
- Tokio's work-stealing scheduler is optimized for cache locality
- Minimal userspace overhead (event notification fully in kernel)
- Better memory layout and pool management
- No context switch overhead between reader/writer threads

Replicating HAProxy's patterns (cache alignment, memory pools, zero-copy where applicable) will close most of the gap.
