# HAProxy-Inspired Epoll Redesign for Lure

## Core Problem with Current Design

Current architecture:
```
Event Loop:
  for each event {
    struct LureConn* conn = &conns[idx]  // L1 hit
    LureBuf* buf = &conn->buf_a          // L1 hit
    read(fd, buf->data, buf->cap)        // L3 miss (accessing huge buffer)
    write(fd2, buf->data, ...)           // L3 miss again
    // Result: 50% cache misses
  }
```

**HAProxy does it differently:**
- Minimal per-connection state in fast path
- Vectored I/O to combine syscalls
- Smart buffering that exploits cache prefetcher
- Connection-local memory pools
- Batched event processing

---

## HAProxy-Inspired Architecture

### 1. Ultra-Compact Connection State (Fast Path Only)

```c
typedef struct {
    int fd_a;
    int fd_b;
    uint64_t id;

    /* Fast path state - ONLY what's needed per event */
    uint32_t flags;           // state machine flags
    uint16_t a_read_want;     // how much to read from A
    uint16_t b_read_want;     // how much to read from B

    /* Offsets into shared buffer pool (not pointers) */
    uint32_t a2b_buf_idx;     // index into buffer pool
    uint32_t b2a_buf_idx;

    uint64_t c2s_bytes;
    uint64_t s2c_bytes;
} __attribute__((aligned(64))) LureConnFast;  // ~64 bytes

/* Separate structure for less-frequently-accessed data */
typedef struct {
    uint64_t conn_id;
    uint32_t a_eof : 1;
    uint32_t b_eof : 1;
    uint32_t a_shutdown : 1;
    uint32_t b_shutdown : 1;
    // ... other state
} LureConnSlow;  // Not in main event loop
```

### 2. Shared Ring Buffer Pool (NUMA-Local)

```c
typedef struct {
    /* Pre-allocated ring buffers, contiguous in memory */
    uint8_t buffers[MAX_CONNS * 2 * SMALL_BUF_SIZE];  // e.g., 2KB per buffer

    /* Ring buffer positions packed together for cache efficiency */
    struct {
        uint16_t read_pos;
        uint16_t write_pos;
    } positions[MAX_CONNS * 2];

} LureBufferPool;

/* Per-thread, allocated on NUMA node */
thread_local LureBufferPool* buf_pool;
```

### 3. Vectored I/O Strategy

Instead of:
```c
// Read from one socket into one buffer
ssize_t n = read(fd_a, buf->data + buf->write_pos, avail);
// Write from one buffer to one socket
ssize_t m = write(fd_b, buf->data + buf->read_pos, avail);
```

Use vectored I/O:
```c
struct iovec iov[4];
// Prepare reads from both sockets
iov[0].iov_base = buf_a_write;
iov[0].iov_len = SMALL_BUF_SIZE;
iov[1].iov_base = buf_b_write;
iov[1].iov_len = SMALL_BUF_SIZE;

// Prepare writes to both sockets
iov[2].iov_base = buf_b_read;
iov[2].iov_len = available_b;
iov[3].iov_base = buf_a_read;
iov[3].iov_len = available_a;

// Execute in batches at end of epoll loop
```

### 4. HAProxy-Style Event Loop

```c
int lure_epoll_thread_run(LureEpollThread* thread) {
    struct epoll_event events[256];
    struct iovec read_batch[MAX_BATCH];
    struct iovec write_batch[MAX_BATCH];

    for (;;) {
        flush_epoll_updates(thread);

        int n = epoll_wait(thread->epoll_fd, events, 256, 50);
        if (n <= 0) continue;

        int read_count = 0, write_count = 0;

        /* Phase 1: Collect all read/write operations */
        for (int i = 0; i < n; ++i) {
            uint32_t idx = events[i].data.u64 >> 1;
            uint32_t side = events[i].data.u64 & 1;

            if (events[i].events & EPOLLIN) {
                // Prepare read operation (don't execute yet)
                prepare_read(thread, idx, side, read_batch, &read_count);
            }

            if (events[i].events & EPOLLOUT) {
                // Prepare write operation (don't execute yet)
                prepare_write(thread, idx, side, write_batch, &write_count);
            }
        }

        /* Phase 2: Execute all I/O operations in batch */
        if (read_count > 0) {
            // Vectored reads: one syscall for many buffers
            execute_batched_reads(read_batch, read_count);
        }

        if (write_count > 0) {
            // Vectored writes: one syscall for many buffers
            execute_batched_writes(write_batch, write_count);
        }

        /* Phase 3: Update connection states */
        for (int i = 0; i < n; ++i) {
            uint32_t idx = events[i].data.u64 >> 1;
            uint32_t side = events[i].data.u64 & 1;

            finalize_event(thread, idx, side);
        }
    }
}
```

### 5. Connection State Machine (Minimal Fast Path)

```c
#define CONN_FLAG_A_READ   0x01
#define CONN_FLAG_B_READ   0x02
#define CONN_FLAG_A_WRITE  0x04
#define CONN_FLAG_B_WRITE  0x08
#define CONN_FLAG_A_EOF    0x10
#define CONN_FLAG_B_EOF    0x20

/* Fast path: just check flags, don't read separate fields */
static inline int should_read_a(LureConnFast* conn) {
    return (conn->flags & CONN_FLAG_A_READ) != 0;
}

static inline void set_read_a(LureConnFast* conn, int val) {
    if (val) conn->flags |= CONN_FLAG_A_READ;
    else conn->flags &= ~CONN_FLAG_A_READ;
}
```

### 6. Connection Pooling (Pre-allocate Everything)

```c
typedef struct {
    LureConnFast* fast;
    LureConnSlow* slow;
    uint32_t* free_stack;

    /* Pre-allocated arrays, sized at startup */
    size_t max_conns;
} LureConnPool;

LureConnPool* create_conn_pool(size_t max_conns) {
    /* Allocate on NUMA node where thread runs */

    LureConnPool* pool = numa_alloc_local(sizeof(*pool));
    pool->fast = numa_alloc_local(max_conns * sizeof(LureConnFast));
    pool->slow = numa_alloc_local(max_conns * sizeof(LureConnSlow));
    pool->free_stack = numa_alloc_local(max_conns * sizeof(uint32_t));

    /* Pre-populate with all indices */
    for (size_t i = 0; i < max_conns; i++) {
        pool->free_stack[i] = max_conns - 1 - i;
    }

    return pool;
}
```

---

## Implementation Roadmap

### Phase 1: Core Restructuring
1. **Redesign LureConnFast** (compact + flags-based)
2. **Create separate LureConnSlow** (cold data)
3. **Implement NUMA-aware allocation**
4. **Build buffer pool** (contiguous, pre-allocated)

### Phase 2: Vectored I/O
1. **Implement prepare_read()** - collect reads without syscalls
2. **Implement prepare_write()** - collect writes without syscalls
3. **Batch execution** - one readv/writev instead of N read/write
4. **Per-connection book-keeping** - track which iov entries belong to which conn

### Phase 3: Hot Path Optimization
1. **Inline critical functions** (flags check, buffer indexing)
2. **Minimize branches** in event processing
3. **Reduce memory accesses** per event
4. **Profile with perf c2c** for cache coherency

### Phase 4: Advanced
1. **TCP_CORK + TCP_QUICKACK** coordination per batch
2. **SO_REUSEPORT** for worker-per-core
3. **Optional io_uring** integration for batched async
4. **NUMA-aware worker distribution**

---

## Expected Performance Improvements

### Current (Userspace Relay)
- IPC: 0.58 (stalled on L3 misses)
- Latency: 300ms (baseline)
- Throughput: ~50K conn/sec

### After HAProxy-Style Redesign
- IPC: 1.5-2.0 (vectored I/O reduces syscalls)
- Latency: 100-150ms (batching + fewer syscalls)
- Throughput: 150K+ conn/sec (reduced per-connection overhead)

### With io_uring (Optional Future)
- IPC: 2.0-2.5
- Latency: 50-80ms (kernel async batching)
- Throughput: 200K+ conn/sec

---

## Why This Matches HAProxy

| Aspect | HAProxy | Lure (Proposed) |
|--------|---------|-----------------|
| **Connection state** | Minimal in fast path | Compact 64-byte struct |
| **Buffering** | Pre-allocated pools | NUMA-local buffer pool |
| **I/O** | Vectored (readv/writev) | Batched vectored I/O |
| **Memory** | NUMA-aware | NUMA-aware allocation |
| **Event loop** | Batch collection → batch exec | Same pattern |
| **Syscalls** | Minimized per batch | Minimized per batch |
| **State machine** | Flags-based | Flags-based |

---

## Files to Rewrite

| File | Scope |
|------|-------|
| `net/src/sock/epoll.c` | Major rewrite (70% of logic) |
| `net/src/sock/epoll.rs` | Minimal changes (interface stable) |
| New: `net/src/sock/epoll_pool.c` | Buffer pool management |
| New: `net/src/sock/epoll_batch.c` | Vectored I/O batching |

---

## Estimated Effort

- **Phase 1**: 3-4 hours (restructure)
- **Phase 2**: 2-3 hours (vectored I/O)
- **Phase 3**: 2-3 hours (optimization + profiling)
- **Phase 4**: 1-2 hours (advanced features)
- **Total**: 8-12 hours for 100-150ms latency
- **With io_uring**: +4-6 hours for 50-80ms

---

## Success Metrics

✓ 100-150ms latency (from 300ms)
✓ 1.5+ IPC (from 0.58)
✓ <5% cache misses in hot path
✓ <50 syscalls per 100 events
✓ Pre-allocation: zero allocation in event loop

---

## Key Differences from Current Design

1. **Current**: One big buffer per connection → L3 misses
   **Proposed**: Shared pool, indexed access → cache-friendly

2. **Current**: Individual read/write syscalls
   **Proposed**: Batch vectored I/O → fewer syscalls

3. **Current**: State spread across multiple fields
   **Proposed**: Flags-based state machine → single dereference

4. **Current**: Pointer-based connection references
   **Proposed**: Index-based with fixed pools → NUMA-aware

5. **Current**: Userspace buffering with copy
   **Proposed**: Minimize copies, batch operations

This is a **significant rewrite** but follows proven HAProxy patterns that achieve 30ms+ latency for similar workloads.
