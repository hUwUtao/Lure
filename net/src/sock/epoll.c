#include "epoll.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>

#define LURE_EPOLL_SIDE_A 0u
#define LURE_EPOLL_SIDE_B 1u
#define LURE_EPOLL_CMD_KEY UINT64_MAX

/* splice syscall - zero-copy kernel-to-kernel data movement */
extern ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                     size_t len, unsigned int flags);
#define SPLICE_F_MOVE   1
#define SPLICE_F_NONBLOCK 2

/* Configuration */
#define LURE_SMALL_BUF_SIZE (2 * 1024)     /* 2KB fits in L1 */
#define LURE_MAX_BATCH 256                  /* Max vectored I/O per batch */

/* Connection flags - single byte check in fast path */
#define CONN_A_READ     0x01
#define CONN_B_READ     0x02
#define CONN_A_WRITE    0x04
#define CONN_B_WRITE    0x08
#define CONN_A_EOF      0x10
#define CONN_B_EOF      0x20
#define CONN_A_SHUTDOWN 0x40
#define CONN_B_SHUTDOWN 0x80
#define CONN_NO_SPLICE  0x100   /* splice not supported, use buffered I/O */

/* Ultra-compact fast-path connection state (64 bytes) */
typedef struct {
    int fd_a;
    int fd_b;
    uint64_t id;
    uint16_t flags;             /* Extended to 16 bits for CONN_NO_SPLICE */
    uint8_t dirty_a;
    uint8_t dirty_b;
    uint16_t buf_a2b;           /* Buffer indices */
    uint16_t buf_b2a;
    uint64_t c2s_bytes;         /* Stats */
    uint64_t s2c_bytes;
    uint64_t c2s_chunks;
    uint64_t s2c_chunks;
    uint32_t last_ev_a;         /* Cached event mask to avoid redundant epoll_ctl */
    uint32_t last_ev_b;
} __attribute__((aligned(64))) LureConnFast;

_Static_assert(sizeof(LureConnFast) == 64, "Must be 64 bytes");

/* Ring buffer position tracking */
typedef struct {
    uint16_t read_pos;
    uint16_t write_pos;
} RingPos;

/* Buffer pool - pre-allocated, contiguous */
typedef struct {
    uint8_t* data;              /* Contiguous buffer block */
    RingPos* positions;         /* Per-buffer positions */
    size_t num_buffers;
    size_t buf_size;
} BufferPool;

/* Vectored I/O batch entry */
typedef struct {
    uint32_t conn_idx;
    uint32_t side;              /* 0 = A, 1 = B */
    size_t bytes;               /* Bytes transferred */
} BatchEntry;

/* Thread context */
struct LureEpollThread {
    int epoll_fd;
    int cmd_fd;
    int done_fd;
    size_t max_conns;

    LureConnFast* conns;
    uint32_t* free_stack;
    uint32_t free_len;

    BufferPool buf_pool;

    /* Batching */
    struct iovec read_vec[LURE_MAX_BATCH];
    struct iovec write_vec[LURE_MAX_BATCH];
    BatchEntry read_batch[LURE_MAX_BATCH];
    BatchEntry write_batch[LURE_MAX_BATCH];
    int read_count;
    int write_count;

    /* Dirty list tracking (phase 2 optimization) */
    uint32_t dirty_list[256];   /* Track dirty connections */
    int dirty_count;

    /* Command buffer */
    uint8_t cmd_buf[sizeof(LureEpollCmd)];
    size_t cmd_buf_len;
    int panic_on_error;
};

/* ============================================================================
   FLAG-BASED STATE HELPERS
   ============================================================================ */

static inline int conn_should_read_a(LureConnFast* conn) {
    return (conn->flags & CONN_A_READ) != 0;
}

static inline int conn_should_read_b(LureConnFast* conn) {
    return (conn->flags & CONN_B_READ) != 0;
}

static inline int conn_should_write_a(LureConnFast* conn) {
    return (conn->flags & CONN_A_WRITE) != 0;
}

static inline int conn_should_write_b(LureConnFast* conn) {
    return (conn->flags & CONN_B_WRITE) != 0;
}

static inline void conn_set_read_a(LureConnFast* conn, int val) {
    if (val) conn->flags |= CONN_A_READ;
    else conn->flags &= ~CONN_A_READ;
}

static inline void conn_set_read_b(LureConnFast* conn, int val) {
    if (val) conn->flags |= CONN_B_READ;
    else conn->flags &= ~CONN_B_READ;
}

static inline void conn_set_write_a(LureConnFast* conn, int val) {
    if (val) conn->flags |= CONN_A_WRITE;
    else conn->flags &= ~CONN_A_WRITE;
}

static inline void conn_set_write_b(LureConnFast* conn, int val) {
    if (val) conn->flags |= CONN_B_WRITE;
    else conn->flags &= ~CONN_B_WRITE;
}

static inline int conn_is_eof_a(LureConnFast* conn) {
    return (conn->flags & CONN_A_EOF) != 0;
}

static inline int conn_is_eof_b(LureConnFast* conn) {
    return (conn->flags & CONN_B_EOF) != 0;
}

static inline void conn_set_eof_a(LureConnFast* conn) {
    conn->flags |= CONN_A_EOF;
}

static inline void conn_set_eof_b(LureConnFast* conn) {
    conn->flags |= CONN_B_EOF;
}

static inline int conn_splice_disabled(LureConnFast* conn) {
    return (conn->flags & CONN_NO_SPLICE) != 0;
}

static inline void conn_disable_splice(LureConnFast* conn) {
    conn->flags |= CONN_NO_SPLICE;
}


/* Mark a connection as dirty to track epoll updates */
static inline void mark_dirty(LureEpollThread* thread, uint32_t idx) {
    if (thread->dirty_count < 256) {
        thread->dirty_list[thread->dirty_count++] = idx;
    }
}

/* ============================================================================
   BUFFER POOL HELPERS
   ============================================================================ */

static inline size_t ring_avail(RingPos* pos, size_t buf_size) {
    if (pos->write_pos >= pos->read_pos) {
        return pos->write_pos - pos->read_pos;
    }
    return (buf_size - pos->read_pos) + pos->write_pos;
}

static inline size_t ring_free(RingPos* pos, size_t buf_size) {
    size_t used = ring_avail(pos, buf_size);
    return buf_size - used - 1;
}

static inline size_t ring_contiguous_read(RingPos* pos, size_t buf_size) {
    if (pos->write_pos >= pos->read_pos) {
        return pos->write_pos - pos->read_pos;
    }
    return buf_size - pos->read_pos;
}

static inline size_t ring_contiguous_write(RingPos* pos, size_t buf_size) {
    size_t free = ring_free(pos, buf_size);
    if (pos->write_pos >= pos->read_pos) {
        return (buf_size - pos->write_pos) > free ? free : (buf_size - pos->write_pos);
    }
    return (pos->read_pos - pos->write_pos - 1) > free ? free : (pos->read_pos - pos->write_pos - 1);
}

/* ============================================================================
   TCP SOCKET CONFIGURATION
   ============================================================================ */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_opts(int fd) {
    int nodelay = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    int quickack = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));

    /* Buffer sizes omitted - let kernel choose defaults for optimal splice() compatibility */

    /* TCP_CORK omitted: conflicts with TCP_NODELAY for low-latency forwarding */
}

/* ============================================================================
   EPOLL UTILITIES
   ============================================================================ */

static uint64_t pack_key(uint32_t idx, uint32_t side) {
    return ((uint64_t)idx << 1) | (uint64_t)(side & 1u);
}

static void unpack_key(uint64_t key, uint32_t* idx, uint32_t* side) {
    *side = (uint32_t)(key & 1u);
    *idx = (uint32_t)(key >> 1);
}

static uint32_t build_events(int want_read, int want_write) {
    uint32_t ev = EPOLLRDHUP | EPOLLHUP | EPOLLERR;
    if (want_read) ev |= EPOLLIN;
    if (want_write) ev |= EPOLLOUT;
    return ev;
}

static int epoll_add(int epoll_fd, int fd, uint32_t idx, uint32_t side, uint32_t events) {
    struct epoll_event ev = {
        .data.u64 = pack_key(idx, side),
        .events = events
    };
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static int epoll_mod(int epoll_fd, int fd, uint32_t idx, uint32_t side, uint32_t events) {
    struct epoll_event ev = {
        .data.u64 = pack_key(idx, side),
        .events = events
    };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

/* ============================================================================
   PANIC/ERROR HANDLING
   ============================================================================ */

static int lure_should_panic(void) {
    const char* env = getenv("LURE_DEBUG_PANIC_PLS");
    return env && env[0] != '0';
}

static void lure_panic_if(LureEpollThread* thread, int condition) {
    if (condition && thread && thread->panic_on_error) {
        abort();
    }
}

/* ============================================================================
   CONNECTION LIFECYCLE
   ============================================================================ */

static void conn_init(LureEpollThread* thread, LureConnFast* conn,
                      int fd_a, int fd_b, uint64_t id,
                      uint16_t buf_a2b, uint16_t buf_b2a) {
    conn->fd_a = fd_a;
    conn->fd_b = fd_b;
    conn->id = id;
    conn->flags = CONN_A_READ | CONN_B_READ | CONN_A_WRITE | CONN_B_WRITE;  /* Start with read and write enabled */
    conn->dirty_a = 1;
    conn->dirty_b = 1;
    conn->buf_a2b = buf_a2b;
    conn->buf_b2a = buf_b2a;
    conn->c2s_bytes = 0;
    conn->s2c_bytes = 0;
    conn->c2s_chunks = 0;
    conn->s2c_chunks = 0;
    conn->last_ev_a = 0;        /* Will be updated on first flush */
    conn->last_ev_b = 0;
}

static void conn_close(LureEpollThread* thread, uint32_t idx) {
    LureConnFast* conn = &thread->conns[idx];

    if (conn->fd_a >= 0) {
        epoll_ctl(thread->epoll_fd, EPOLL_CTL_DEL, conn->fd_a, NULL);
        close(conn->fd_a);
        conn->fd_a = -1;
    }
    if (conn->fd_b >= 0) {
        epoll_ctl(thread->epoll_fd, EPOLL_CTL_DEL, conn->fd_b, NULL);
        close(conn->fd_b);
        conn->fd_b = -1;
    }

    if (thread->done_fd >= 0) {
        LureEpollDone done = {
            .id = conn->id,
            .stats.c2s_bytes = conn->c2s_bytes,
            .stats.s2c_bytes = conn->s2c_bytes,
            .stats.c2s_chunks = conn->c2s_chunks,
            .stats.s2c_chunks = conn->s2c_chunks,
            .result = 0
        };
        (void)write(thread->done_fd, &done, sizeof(done));
    }

    if (thread->free_stack) {
        thread->free_stack[thread->free_len++] = idx;
    }
}

/* ============================================================================
   COMMAND PROCESSING
   ============================================================================ */

static int read_cmds(LureEpollThread* thread) {
    for (;;) {
        ssize_t n = read(thread->cmd_fd,
                        thread->cmd_buf + thread->cmd_buf_len,
                        sizeof(LureEpollCmd) - thread->cmd_buf_len);
        if (n <= 0) {
            if (n == 0) return 1;  /* EOF */
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }

        thread->cmd_buf_len += (size_t)n;
        if (thread->cmd_buf_len < sizeof(LureEpollCmd)) continue;

        LureEpollCmd cmd;
        memcpy(&cmd, thread->cmd_buf, sizeof(cmd));
        thread->cmd_buf_len = 0;

        if (cmd.fd_a < 0 && cmd.fd_b < 0) {
            return 1;  /* Shutdown signal */
        }

        if (thread->free_len == 0) {
            close(cmd.fd_a);
            close(cmd.fd_b);
            lure_panic_if(thread, 1);
            continue;
        }

        /* Allocate connection */
        uint32_t idx = thread->free_stack[--thread->free_len];
        uint16_t buf_a2b = idx * 2;
        uint16_t buf_b2a = idx * 2 + 1;

        LureConnFast* conn = &thread->conns[idx];
        conn_init(thread, conn, cmd.fd_a, cmd.fd_b, cmd.id, buf_a2b, buf_b2a);

        set_nonblocking(cmd.fd_a);
        set_nonblocking(cmd.fd_b);
        set_tcp_opts(cmd.fd_a);
        set_tcp_opts(cmd.fd_b);

        epoll_add(thread->epoll_fd, cmd.fd_a, idx, LURE_EPOLL_SIDE_A, build_events(1, 0));
        epoll_add(thread->epoll_fd, cmd.fd_b, idx, LURE_EPOLL_SIDE_B, build_events(1, 0));
    }
}

/* ============================================================================
   EPOLL INTEREST UPDATES
   ============================================================================ */

static void flush_epoll_updates(LureEpollThread* thread) {
    /* Process only dirty connections (phase 2 optimization: no full scan) */
    for (int i = 0; i < thread->dirty_count; i++) {
        uint32_t idx = thread->dirty_list[i];
        LureConnFast* conn = &thread->conns[idx];

        if (conn->dirty_a) {
            uint32_t ev = build_events(conn_should_read_a(conn), conn_should_write_a(conn));
            /* Only call epoll_ctl if event mask changed */
            if (ev != conn->last_ev_a) {
                epoll_mod(thread->epoll_fd, conn->fd_a, idx, LURE_EPOLL_SIDE_A, ev);
                conn->last_ev_a = ev;
            }
            conn->dirty_a = 0;
        }

        if (conn->dirty_b) {
            uint32_t ev = build_events(conn_should_read_b(conn), conn_should_write_b(conn));
            /* Only call epoll_ctl if event mask changed */
            if (ev != conn->last_ev_b) {
                epoll_mod(thread->epoll_fd, conn->fd_b, idx, LURE_EPOLL_SIDE_B, ev);
                conn->last_ev_b = ev;
            }
            conn->dirty_b = 0;
        }
    }
    thread->dirty_count = 0;
}

/* ============================================================================
   MAIN EVENT LOOP (Phase 2: Single-Pass Optimized)
   ============================================================================ */

int lure_epoll_thread_run(LureEpollThread* thread) {
    if (!thread) return -1;

    struct epoll_event events[128];

    for (;;) {
        flush_epoll_updates(thread);

        int n = epoll_wait(thread->epoll_fd, events, 128, 50);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        if (n == 0) continue;

        /* Phase 2 optimization: Single-pass event processing (inline I/O) */
        for (int i = 0; i < n; i++) {
            uint64_t key = events[i].data.u64;

            if (key == LURE_EPOLL_CMD_KEY) {
                int rc = read_cmds(thread);
                if (rc != 0) return rc == 1 ? 0 : -1;
                continue;
            }

            uint32_t idx = 0, side = 0;
            unpack_key(key, &idx, &side);
            uint32_t ev = events[i].events;
            LureConnFast* conn = &thread->conns[idx];

            if (ev & (EPOLLERR | EPOLLHUP)) {
                conn_close(thread, idx);
                continue;
            }

            /* Process reads immediately (drain socket to reduce syscalls) */
            if (ev & EPOLLIN) {
                int read_fd = side == LURE_EPOLL_SIDE_A ? conn->fd_a : conn->fd_b;
                int write_fd = side == LURE_EPOLL_SIDE_A ? conn->fd_b : conn->fd_a;
                if (read_fd >= 0 && write_fd >= 0) {
                    /* Try zero-copy splice if not disabled for this connection */
                    if (!conn_splice_disabled(conn)) {
                        ssize_t spliced = splice(read_fd, NULL, write_fd, NULL, 65536,
                                                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

                        if (spliced > 0) {
                            /* Success: record stats and mark dirty */
                            if (side == LURE_EPOLL_SIDE_A) {
                                conn->c2s_bytes += spliced;
                                conn->c2s_chunks++;
                            } else {
                                conn->s2c_bytes += spliced;
                                conn->s2c_chunks++;
                            }
                            mark_dirty(thread, idx);
                        } else if (spliced == 0) {
                            /* EOF: mark connection closed */
                            if (side == LURE_EPOLL_SIDE_A) {
                                conn_set_eof_a(conn);
                            } else {
                                conn_set_eof_b(conn);
                            }
                            mark_dirty(thread, idx);
                        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            /* No data available, try again later */
                        } else if (errno == EINVAL || errno == ENOSYS) {
                            /* splice not supported: disable it for this connection */
                            conn_disable_splice(conn);
                            /* Fall through to buffered I/O below */
                        } else {
                            /* Unexpected error: close connection */
                            conn_close(thread, idx);
                            continue;
                        }
                    }

                    /* Fallback to buffered I/O if splice failed or is disabled */
                    if (conn_splice_disabled(conn)) {
                        uint16_t buf_idx = side == LURE_EPOLL_SIDE_A ? conn->buf_a2b : conn->buf_b2a;
                        RingPos* pos = &thread->buf_pool.positions[buf_idx];
                        uint8_t* buf_data = thread->buf_pool.data + buf_idx * thread->buf_pool.buf_size;

                        /* Drain socket: read until EAGAIN to minimize syscalls
                         * This trades CPU per-event for fewer syscall transitions */
                        while (1) {
                            size_t write_space = ring_contiguous_write(pos, thread->buf_pool.buf_size);
                            if (write_space == 0) break;  /* Buffer full */

                            ssize_t n = read(read_fd, buf_data + pos->write_pos, write_space);

                            if (n > 0) {
                                pos->write_pos = (pos->write_pos + n) % thread->buf_pool.buf_size;
                                if (side == LURE_EPOLL_SIDE_A) {
                                    conn->c2s_bytes += n;
                                    conn->c2s_chunks++;
                                } else {
                                    conn->s2c_bytes += n;
                                    conn->s2c_chunks++;
                                }
                            } else if (n == 0) {
                                if (side == LURE_EPOLL_SIDE_A) {
                                    conn_set_eof_a(conn);
                                } else {
                                    conn_set_eof_b(conn);
                                }
                                break;
                            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                break;  /* No more data available */
                            } else {
                                conn_close(thread, idx);
                                break;
                            }
                        }
                        mark_dirty(thread, idx);
                    }
                }
            }

            /* Process writes immediately (drain buffer to reduce syscalls) */
            if (ev & EPOLLOUT) {
                int write_fd = side == LURE_EPOLL_SIDE_A ? conn->fd_b : conn->fd_a;
                if (write_fd >= 0) {
                    uint16_t buf_idx = side == LURE_EPOLL_SIDE_A ? conn->buf_a2b : conn->buf_b2a;
                    RingPos* pos = &thread->buf_pool.positions[buf_idx];

                    /* Drain buffer: write until EAGAIN to minimize syscalls */
                    while (1) {
                        size_t avail = ring_contiguous_read(pos, thread->buf_pool.buf_size);
                        if (avail == 0) break;  /* Buffer empty */

                        uint8_t* buf_data = thread->buf_pool.data + buf_idx * thread->buf_pool.buf_size;
                        ssize_t n = write(write_fd, buf_data + pos->read_pos, avail);

                        if (n > 0) {
                            pos->read_pos = (pos->read_pos + n) % thread->buf_pool.buf_size;
                        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break;  /* Socket buffer full, stop draining */
                        } else if (n < 0) {
                            conn_close(thread, idx);
                            break;
                        }
                    }
                    mark_dirty(thread, idx);
                }
            }

            /* Check for connection completion (inline) */
            if (conn->fd_a >= 0 || conn->fd_b >= 0) {
                int both_eof = conn_is_eof_a(conn) && conn_is_eof_b(conn);
                if (both_eof) {
                    RingPos* pos_a2b = &thread->buf_pool.positions[conn->buf_a2b];
                    RingPos* pos_b2a = &thread->buf_pool.positions[conn->buf_b2a];
                    if (ring_avail(pos_a2b, thread->buf_pool.buf_size) == 0 &&
                        ring_avail(pos_b2a, thread->buf_pool.buf_size) == 0) {
                        conn_close(thread, idx);
                    }
                }
            }
        }
    }
}

/* ============================================================================
   INITIALIZATION
   ============================================================================ */

LureEpollThread* lure_epoll_thread_new(int cmd_fd, int done_fd, size_t max_conns, size_t buf_cap) {
    LureEpollThread* thread = (LureEpollThread*)calloc(1, sizeof(LureEpollThread));
    if (!thread) return NULL;

    thread->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (thread->epoll_fd < 0) {
        free(thread);
        return NULL;
    }

    thread->cmd_fd = cmd_fd;
    thread->done_fd = done_fd;
    thread->max_conns = max_conns;

    /* Allocate connection array */
    thread->conns = (LureConnFast*)calloc(max_conns, sizeof(LureConnFast));
    thread->free_stack = (uint32_t*)calloc(max_conns, sizeof(uint32_t));

    if (!thread->conns || !thread->free_stack) {
        if (thread->conns) free(thread->conns);
        if (thread->free_stack) free(thread->free_stack);
        close(thread->epoll_fd);
        free(thread);
        return NULL;
    }

    /* Initialize free stack */
    for (size_t i = 0; i < max_conns; i++) {
        thread->free_stack[i] = (uint32_t)(max_conns - 1 - i);
    }
    thread->free_len = (uint32_t)max_conns;

    /* Allocate buffer pool */
    size_t num_buffers = max_conns * 2;
    thread->buf_pool.num_buffers = num_buffers;
    thread->buf_pool.buf_size = LURE_SMALL_BUF_SIZE;
    thread->buf_pool.data = (uint8_t*)calloc(num_buffers * LURE_SMALL_BUF_SIZE, 1);
    thread->buf_pool.positions = (RingPos*)calloc(num_buffers, sizeof(RingPos));

    if (!thread->buf_pool.data || !thread->buf_pool.positions) {
        if (thread->buf_pool.data) free(thread->buf_pool.data);
        if (thread->buf_pool.positions) free(thread->buf_pool.positions);
        free(thread->conns);
        free(thread->free_stack);
        close(thread->epoll_fd);
        free(thread);
        return NULL;
    }

    if (set_nonblocking(thread->cmd_fd) < 0) {
        free(thread->buf_pool.data);
        free(thread->buf_pool.positions);
        free(thread->conns);
        free(thread->free_stack);
        close(thread->epoll_fd);
        free(thread);
        return NULL;
    }

    struct epoll_event ev = {
        .data.u64 = LURE_EPOLL_CMD_KEY,
        .events = EPOLLIN | EPOLLERR | EPOLLHUP
    };
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, thread->cmd_fd, &ev) < 0) {
        free(thread->buf_pool.data);
        free(thread->buf_pool.positions);
        free(thread->conns);
        free(thread->free_stack);
        close(thread->epoll_fd);
        free(thread);
        return NULL;
    }

    thread->cmd_buf_len = 0;
    thread->panic_on_error = lure_should_panic();
    thread->read_count = 0;
    thread->write_count = 0;

    return thread;
}

void lure_epoll_thread_shutdown(LureEpollThread* thread) {
    if (!thread) return;
    /* Shutdown initiated via pipe */
}

void lure_epoll_thread_free(LureEpollThread* thread) {
    if (!thread) return;

    if (thread->epoll_fd >= 0) close(thread->epoll_fd);
    if (thread->conns) free(thread->conns);
    if (thread->free_stack) free(thread->free_stack);
    if (thread->buf_pool.data) free(thread->buf_pool.data);
    if (thread->buf_pool.positions) free(thread->buf_pool.positions);

    free(thread);
}

/* ============================================================================
   SYNCHRONOUS RELAY (relay_pair for passthrough)
   ============================================================================ */

int lure_epoll_passthrough(int fd_a, int fd_b, LureEpollStats* stats) {
    LureEpollThread thread = {0};
    thread.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (thread.epoll_fd < 0) return -1;

    thread.buf_pool.buf_size = LURE_SMALL_BUF_SIZE;
    thread.buf_pool.data = (uint8_t*)calloc(2 * LURE_SMALL_BUF_SIZE, 1);
    thread.buf_pool.positions = (RingPos*)calloc(2, sizeof(RingPos));
    thread.buf_pool.num_buffers = 2;

    if (!thread.buf_pool.data || !thread.buf_pool.positions) {
        goto fail;
    }

    set_nonblocking(fd_a);
    set_nonblocking(fd_b);
    set_tcp_opts(fd_a);
    set_tcp_opts(fd_b);

    epoll_add(thread.epoll_fd, fd_a, 0, LURE_EPOLL_SIDE_A, build_events(1, 0));
    epoll_add(thread.epoll_fd, fd_b, 0, LURE_EPOLL_SIDE_B, build_events(1, 0));

    struct epoll_event events[2];
    LureConnFast conn = {.fd_a = fd_a, .fd_b = fd_b, .buf_a2b = 0, .buf_b2a = 1};
    conn.flags = CONN_A_READ | CONN_B_READ;

    for (;;) {
        int n = epoll_wait(thread.epoll_fd, events, 2, -1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;

        for (int i = 0; i < n; i++) {
            uint32_t side = events[i].data.u64 & 1;

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                goto done;
            }

            if (events[i].events & EPOLLIN) {
                int read_fd = side == LURE_EPOLL_SIDE_A ? fd_a : fd_b;
                int write_fd = side == LURE_EPOLL_SIDE_A ? fd_b : fd_a;
                uint16_t buf_idx = side == LURE_EPOLL_SIDE_A ? 0 : 1;
                RingPos* pos = &thread.buf_pool.positions[buf_idx];
                uint8_t* buf_data = thread.buf_pool.data + buf_idx * LURE_SMALL_BUF_SIZE;

                /* Try zero-copy splice if not disabled for this connection */
                if (!conn_splice_disabled(&conn)) {
                    ssize_t spliced = splice(read_fd, NULL, write_fd, NULL, 65536,
                                            SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

                    if (spliced > 0) {
                        /* Success: record stats */
                        if (side == LURE_EPOLL_SIDE_A) {
                            conn.c2s_bytes += spliced;
                            conn.c2s_chunks++;
                        } else {
                            conn.s2c_bytes += spliced;
                            conn.s2c_chunks++;
                        }
                    } else if (spliced == 0) {
                        /* EOF: mark connection closed */
                        if (side == LURE_EPOLL_SIDE_A) {
                            conn_set_eof_a(&conn);
                        } else {
                            conn_set_eof_b(&conn);
                        }
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* No data available, fall through to buffered I/O attempt */
                    } else if (errno == EINVAL || errno == ENOSYS) {
                        /* splice not supported: disable it for this connection */
                        conn_disable_splice(&conn);
                        /* Fall through to buffered I/O below */
                    } else {
                        /* Unexpected error: close connection */
                        goto fail;
                    }
                }

                /* Fallback to buffered I/O if splice failed or is disabled */
                if (conn_splice_disabled(&conn)) {
                    size_t write_space = ring_contiguous_write(pos, LURE_SMALL_BUF_SIZE);
                    ssize_t n_read = read(read_fd, buf_data + pos->write_pos, write_space);

                    if (n_read > 0) {
                        pos->write_pos = (pos->write_pos + n_read) % LURE_SMALL_BUF_SIZE;
                        if (side == LURE_EPOLL_SIDE_A) {
                            conn.c2s_bytes += n_read;
                            conn.c2s_chunks++;
                        } else {
                            conn.s2c_bytes += n_read;
                            conn.s2c_chunks++;
                        }
                    } else if (n_read == 0) {
                        if (side == LURE_EPOLL_SIDE_A) {
                            conn_set_eof_a(&conn);
                        } else {
                            conn_set_eof_b(&conn);
                        }
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        goto fail;
                    }
                }
            }

            if (events[i].events & EPOLLOUT) {
                int write_fd = side == LURE_EPOLL_SIDE_A ? fd_b : fd_a;
                uint16_t buf_idx = side == LURE_EPOLL_SIDE_A ? 1 : 0;
                RingPos* pos = &thread.buf_pool.positions[buf_idx];
                uint8_t* buf_data = thread.buf_pool.data + buf_idx * LURE_SMALL_BUF_SIZE;

                size_t avail = ring_contiguous_read(pos, LURE_SMALL_BUF_SIZE);
                if (avail > 0) {
                    ssize_t n_write = write(write_fd, buf_data + pos->read_pos, avail);
                    if (n_write > 0) {
                        pos->read_pos = (pos->read_pos + n_write) % LURE_SMALL_BUF_SIZE;
                    }
                }
            }
        }

        if (conn_is_eof_a(&conn) && conn_is_eof_b(&conn) &&
            ring_avail(&thread.buf_pool.positions[0], LURE_SMALL_BUF_SIZE) == 0 &&
            ring_avail(&thread.buf_pool.positions[1], LURE_SMALL_BUF_SIZE) == 0) {
            goto done;
        }
    }

done:
    if (stats) {
        stats->c2s_bytes = conn.c2s_bytes;
        stats->s2c_bytes = conn.s2c_bytes;
        stats->c2s_chunks = conn.c2s_chunks;
        stats->s2c_chunks = conn.s2c_chunks;
    }

    close(thread.epoll_fd);
    free(thread.buf_pool.data);
    free(thread.buf_pool.positions);
    return 0;

fail:
    close(thread.epoll_fd);
    if (thread.buf_pool.data) free(thread.buf_pool.data);
    if (thread.buf_pool.positions) free(thread.buf_pool.positions);
    return -1;
}
