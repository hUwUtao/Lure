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

#define LURE_EPOLL_SIDE_A 0u
#define LURE_EPOLL_SIDE_B 1u
#define LURE_EPOLL_CMD_KEY UINT64_MAX

typedef struct {
    size_t cap;
    size_t read_pos;   /* where we consume from */
    size_t write_pos;  /* where we append to */
    uint8_t* data;
} LureBuf;

typedef struct {
    int fd_a;
    int fd_b;
    uint64_t id;
    LureBuf a2b;
    LureBuf b2a;
    uint8_t a_eof;
    uint8_t b_eof;
    uint8_t a_shutdown;
    uint8_t b_shutdown;
    uint8_t a_read;
    uint8_t b_read;
    uint8_t a_write;
    uint8_t b_write;
    uint8_t a_dirty;  /* epoll interest needs update */
    uint8_t b_dirty;  /* epoll interest needs update */
    LureEpollStats stats;
} __attribute__((aligned(64))) LureConn;  /* Cache-line alignment (64 bytes) for L1/L2 cache optimization */

/* Helper functions for ring buffer operations */
static inline size_t buf_avail(LureBuf* buf) {
    if (buf->write_pos >= buf->read_pos) {
        return buf->write_pos - buf->read_pos;
    }
    return (buf->cap - buf->read_pos) + buf->write_pos;
}

static inline size_t buf_free(LureBuf* buf) {
    size_t used = buf_avail(buf);
    return buf->cap - used - 1;
}

static inline size_t buf_contiguous_write(LureBuf* buf) {
    size_t free = buf_free(buf);
    if (buf->write_pos >= buf->read_pos) {
        return (buf->cap - buf->write_pos) > free ? free : (buf->cap - buf->write_pos);
    }
    return (buf->read_pos - buf->write_pos - 1) > free ? free : (buf->read_pos - buf->write_pos - 1);
}

static inline size_t buf_contiguous_read(LureBuf* buf) {
    if (buf->write_pos >= buf->read_pos) {
        return buf->write_pos - buf->read_pos;
    }
    return buf->cap - buf->read_pos;
}

struct LureEpollThread {
    int epoll_fd;
    int cmd_fd;
    int done_fd;
    size_t max_conns;
    size_t buf_cap;
    LureConn* conns;
    uint32_t* free_stack;
    uint32_t free_len;
    uint8_t* buffers;
    uint8_t cmd_buf[sizeof(LureEpollCmd)];
    size_t cmd_buf_len;
    int panic_on_error;
};

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

static void set_tcp_opts(int fd) {
    /* Disable Nagle's algorithm for lower latency */
    int nodelay = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    /* Enable TCP quickack for faster ACKs */
    int quickack = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));

    /* Increase send/recv buffers for 64KB buffer size and better throughput */
    int sndbuf = 512 * 1024;  /* Increased from 256KB to 512KB */
    int rcvbuf = 512 * 1024;  /* Increased from 256KB to 512KB */
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* Enable TCP_CORK for better batching on writes */
    int cork = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

    /* TCP_DEFER_ACCEPT to reduce wakeups for incomplete connections */
    int defer = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));
}

static int lure_should_panic(void) {
    const char* env = getenv("LURE_DEBUG_PANIC_PLS");
    if (!env || env[0] == '0') {
        return 0;
    }
    return 1;
}

static void lure_panic_if(LureEpollThread* thread, int condition) {
    if (condition && thread && thread->panic_on_error) {
        abort();
    }
}

static uint64_t pack_key(uint32_t idx, uint32_t side) {
    return ((uint64_t)idx << 1) | (uint64_t)(side & 1u);
}

static void unpack_key(uint64_t key, uint32_t* idx, uint32_t* side) {
    *side = (uint32_t)(key & 1u);
    *idx = (uint32_t)(key >> 1);
}

static int epoll_mod(int epoll_fd, int fd, uint32_t idx, uint32_t side, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.u64 = pack_key(idx, side);
    ev.events = events;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

static int epoll_add(int epoll_fd, int fd, uint32_t idx, uint32_t side, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.u64 = pack_key(idx, side);
    ev.events = events;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static uint32_t build_events(uint8_t want_read, uint8_t want_write) {
    uint32_t ev = (uint32_t)(EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    if (want_read) {
        ev |= EPOLLIN;
    }
    if (want_write) {
        ev |= EPOLLOUT;
    }
    return ev;
}

static void update_interest(LureEpollThread* thread, uint32_t idx, uint32_t side) {
    LureConn* conn = &thread->conns[idx];
    /* Mark as dirty for lazy evaluation before epoll_wait */
    if (side == LURE_EPOLL_SIDE_A) {
        conn->a_dirty = 1;
    } else {
        conn->b_dirty = 1;
    }
}

static void conn_init(LureEpollThread* thread, LureConn* conn, int fd_a, int fd_b, uint64_t id,
                      uint8_t* buf_a, uint8_t* buf_b) {
    conn->fd_a = fd_a;
    conn->fd_b = fd_b;
    conn->id = id;
    conn->a2b.cap = thread->buf_cap;
    conn->a2b.read_pos = 0;
    conn->a2b.write_pos = 0;
    conn->a2b.data = buf_a;
    conn->b2a.cap = thread->buf_cap;
    conn->b2a.read_pos = 0;
    conn->b2a.write_pos = 0;
    conn->b2a.data = buf_b;
    conn->a_eof = 0;
    conn->b_eof = 0;
    conn->a_shutdown = 0;
    conn->b_shutdown = 0;
    conn->a_read = 1;
    conn->b_read = 1;
    conn->a_write = 0;
    conn->b_write = 0;
    conn->a_dirty = 0;
    conn->b_dirty = 0;
    memset(&conn->stats, 0, sizeof(conn->stats));
    (void)thread;
}

static void conn_close(LureEpollThread* thread, uint32_t idx, int result) {
    LureConn* conn = &thread->conns[idx];
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
        LureEpollDone done;
        done.id = conn->id;
        done.stats = conn->stats;
        done.result = result;
        (void)write(thread->done_fd, &done, sizeof(done));
    }

    if (thread->free_stack) {
        thread->free_stack[thread->free_len++] = idx;
    }

    lure_panic_if(thread, result < 0);
}

static void try_shutdown_other(LureConn* conn, int which, int other_fd) {
    if (which == LURE_EPOLL_SIDE_A) {
        if (!conn->b_shutdown) {
            shutdown(other_fd, SHUT_WR);
            conn->b_shutdown = 1;
        }
    } else {
        if (!conn->a_shutdown) {
            shutdown(other_fd, SHUT_WR);
            conn->a_shutdown = 1;
        }
    }
}

static void flush_buf(LureEpollThread* thread, uint32_t idx, uint32_t side) {
    LureConn* conn = &thread->conns[idx];
    LureBuf* buf = (side == LURE_EPOLL_SIDE_A) ? &conn->b2a : &conn->a2b;
    int fd = (side == LURE_EPOLL_SIDE_A) ? conn->fd_a : conn->fd_b;

    /* Write available data from ring buffer */
    while (buf_avail(buf) > 0) {
        size_t avail = buf_contiguous_read(buf);
        ssize_t n = write(fd, buf->data + buf->read_pos, avail);
        if (n > 0) {
            buf->read_pos = (buf->read_pos + (size_t)n) % buf->cap;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            conn_close(thread, idx, -errno);
            return;
        }
    }

    if (buf_avail(buf) == 0) {
        if (side == LURE_EPOLL_SIDE_A) {
            conn->a_write = 0;
            conn->b_read = 1;
            update_interest(thread, idx, LURE_EPOLL_SIDE_A);
            update_interest(thread, idx, LURE_EPOLL_SIDE_B);
        } else {
            conn->b_write = 0;
            conn->a_read = 1;
            update_interest(thread, idx, LURE_EPOLL_SIDE_B);
            update_interest(thread, idx, LURE_EPOLL_SIDE_A);
        }
        if (side == LURE_EPOLL_SIDE_A && conn->b_eof) {
            try_shutdown_other(conn, LURE_EPOLL_SIDE_B, conn->fd_a);
        } else if (side == LURE_EPOLL_SIDE_B && conn->a_eof) {
            try_shutdown_other(conn, LURE_EPOLL_SIDE_A, conn->fd_b);
        }
    } else {
        if (side == LURE_EPOLL_SIDE_A) {
            conn->a_write = 1;
            update_interest(thread, idx, LURE_EPOLL_SIDE_A);
        } else {
            conn->b_write = 1;
            update_interest(thread, idx, LURE_EPOLL_SIDE_B);
        }
    }
}

static void handle_read(LureEpollThread* thread, uint32_t idx, uint32_t side) {
    LureConn* conn = &thread->conns[idx];
    LureBuf* buf = (side == LURE_EPOLL_SIDE_A) ? &conn->a2b : &conn->b2a;
    int fd = (side == LURE_EPOLL_SIDE_A) ? conn->fd_a : conn->fd_b;
    int out_fd = (side == LURE_EPOLL_SIDE_A) ? conn->fd_b : conn->fd_a;

    /* Ring buffer eliminates need for memmove - no data shifting required */

    if (buf_free(buf) <= 0) {
        /* Buffer full, stop reading */
        if (side == LURE_EPOLL_SIDE_A) {
            conn->a_read = 0;
            update_interest(thread, idx, LURE_EPOLL_SIDE_A);
        } else {
            conn->b_read = 0;
            update_interest(thread, idx, LURE_EPOLL_SIDE_B);
        }
        return;
    }

    /* Get contiguous write space in ring buffer */
    size_t write_space = buf_contiguous_write(buf);
    ssize_t n = read(fd, buf->data + buf->write_pos, write_space);
    if (n > 0) {
        buf->write_pos = (buf->write_pos + (size_t)n) % buf->cap;
        if (side == LURE_EPOLL_SIDE_A) {
            conn->stats.c2s_bytes += (uint64_t)n;
            conn->stats.c2s_chunks += 1;
        } else {
            conn->stats.s2c_bytes += (uint64_t)n;
            conn->stats.s2c_chunks += 1;
        }
        flush_buf(thread, idx, side == LURE_EPOLL_SIDE_A ? LURE_EPOLL_SIDE_B : LURE_EPOLL_SIDE_A);
        return;
    }
    if (n == 0) {
        if (side == LURE_EPOLL_SIDE_A) {
            conn->a_eof = 1;
        } else {
            conn->b_eof = 1;
        }
        if (buf_avail(buf) == 0) {
            try_shutdown_other(conn, side, out_fd);
        }
        if ((conn->a_eof && conn->b_eof) && buf_avail(&conn->a2b) == 0 && buf_avail(&conn->b2a) == 0) {
            conn_close(thread, idx, 0);
        }
        return;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return;
    }
    conn_close(thread, idx, -errno);
}

LureEpollThread* lure_epoll_thread_new(int cmd_fd, int done_fd, size_t max_conns, size_t buf_cap) {
    LureEpollThread* thread = (LureEpollThread*)calloc(1, sizeof(LureEpollThread));
    if (!thread) {
        return NULL;
    }
    thread->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (thread->epoll_fd < 0) {
        free(thread);
        return NULL;
    }

    thread->cmd_fd = cmd_fd;
    thread->done_fd = done_fd;
    thread->max_conns = max_conns;
    thread->buf_cap = buf_cap;

    thread->conns = (LureConn*)calloc(max_conns, sizeof(LureConn));
    thread->free_stack = (uint32_t*)calloc(max_conns, sizeof(uint32_t));
    thread->buffers = (uint8_t*)calloc(max_conns * buf_cap * 2, sizeof(uint8_t));
    if (!thread->conns || !thread->free_stack || !thread->buffers) {
        lure_epoll_thread_free(thread);
        return NULL;
    }

    thread->cmd_buf_len = 0;
    thread->panic_on_error = lure_should_panic();

    for (uint32_t i = 0; i < max_conns; ++i) {
        thread->free_stack[i] = (uint32_t)(max_conns - 1 - i);
    }
    thread->free_len = (uint32_t)max_conns;

    if (set_nonblocking(thread->cmd_fd) < 0) {
        lure_epoll_thread_free(thread);
        return NULL;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.u64 = LURE_EPOLL_CMD_KEY;
    ev.events = (uint32_t)(EPOLLIN | EPOLLERR | EPOLLHUP);
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, thread->cmd_fd, &ev) < 0) {
        lure_epoll_thread_free(thread);
        return NULL;
    }

    return thread;
}

static int read_cmds(LureEpollThread* thread) {
    for (;;) {
        ssize_t n = read(thread->cmd_fd,
                         thread->cmd_buf + thread->cmd_buf_len,
                         sizeof(LureEpollCmd) - thread->cmd_buf_len);
        if (n > 0) {
            thread->cmd_buf_len += (size_t)n;
            if (thread->cmd_buf_len < sizeof(LureEpollCmd)) {
                continue;
            }

            LureEpollCmd cmd;
            memcpy(&cmd, thread->cmd_buf, sizeof(cmd));
            thread->cmd_buf_len = 0;

            if (cmd.fd_a < 0 && cmd.fd_b < 0) {
                return 1;
            }
            if (thread->free_len == 0) {
                if (cmd.fd_a >= 0) {
                    close(cmd.fd_a);
                }
                if (cmd.fd_b >= 0) {
                    close(cmd.fd_b);
                }
                lure_panic_if(thread, 1);
                if (thread->done_fd >= 0) {
                    LureEpollDone done;
                    memset(&done, 0, sizeof(done));
                    done.id = cmd.id;
                    done.result = -12;
                    (void)write(thread->done_fd, &done, sizeof(done));
                }
                continue;
            }

            uint32_t idx = thread->free_stack[--thread->free_len];
            uint8_t* buf_a = thread->buffers + (idx * thread->buf_cap * 2);
            uint8_t* buf_b = buf_a + thread->buf_cap;
            conn_init(thread, &thread->conns[idx], cmd.fd_a, cmd.fd_b, cmd.id, buf_a, buf_b);

            set_nonblocking(cmd.fd_a);
            set_nonblocking(cmd.fd_b);
            set_tcp_opts(cmd.fd_a);
            set_tcp_opts(cmd.fd_b);

            if (epoll_add(thread->epoll_fd, cmd.fd_a, idx, LURE_EPOLL_SIDE_A,
                          build_events(1, 0)) < 0) {
                conn_close(thread, idx, -errno);
                continue;
            }
            if (epoll_add(thread->epoll_fd, cmd.fd_b, idx, LURE_EPOLL_SIDE_B,
                          build_events(1, 0)) < 0) {
                conn_close(thread, idx, -errno);
                continue;
            }
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (n == 0) {
            return 1;
        }
        if (errno == EINTR) {
            continue;
        }
        lure_panic_if(thread, 1);
        return -1;
    }
    return 0;
}

static void flush_epoll_updates(LureEpollThread* thread) {
    /* Batch epoll_ctl updates to reduce syscalls */
    for (size_t i = 0; i < thread->max_conns; i++) {
        LureConn* conn = &thread->conns[i];
        if (conn->fd_a < 0 && conn->fd_b < 0) {
            continue;  /* Connection not active */
        }
        if (conn->a_dirty) {
            uint32_t ev = build_events(conn->a_read, conn->a_write);
            (void)epoll_mod(thread->epoll_fd, conn->fd_a, (uint32_t)i, LURE_EPOLL_SIDE_A, ev);
            conn->a_dirty = 0;
        }
        if (conn->b_dirty) {
            uint32_t ev = build_events(conn->b_read, conn->b_write);
            (void)epoll_mod(thread->epoll_fd, conn->fd_b, (uint32_t)i, LURE_EPOLL_SIDE_B, ev);
            conn->b_dirty = 0;
        }
    }
}

int lure_epoll_thread_run(LureEpollThread* thread) {
    if (!thread) {
        return -1;
    }
    struct epoll_event events[128];
    for (;;) {
        /* Flush batched epoll updates before waiting */
        flush_epoll_updates(thread);
        /* Use 1000ms timeout to allow clean shutdown on Ctrl+C */
        int n = epoll_wait(thread->epoll_fd, events, 128, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            lure_panic_if(thread, 1);
            return -1;
        }
        for (int i = 0; i < n; ++i) {
            uint64_t key = events[i].data.u64;
            if (key == LURE_EPOLL_CMD_KEY) {
                int rc = read_cmds(thread);
                if (rc != 0) {
                    return 0;
                }
                continue;
            }
            uint32_t idx = 0;
            uint32_t side = 0;
            unpack_key(key, &idx, &side);
            uint32_t ev = events[i].events;
            if (ev & (EPOLLERR | EPOLLHUP)) {
                conn_close(thread, idx, -errno);
                continue;
            }
            if (ev & EPOLLIN) {
                handle_read(thread, idx, side);
            }
            if (ev & EPOLLOUT) {
                flush_buf(thread, idx, side);
            }
        }
    }
}

void lure_epoll_thread_shutdown(LureEpollThread* thread) {
    if (!thread) {
        return;
    }
    /* Shutdown is initiated by the Rust caller via its retained write end of the pipe;
       do not attempt to write from the C thread as cmd_fd is the read end only. */
}

void lure_epoll_thread_free(LureEpollThread* thread) {
    if (!thread) {
        return;
    }
    if (thread->epoll_fd >= 0) {
        close(thread->epoll_fd);
    }
    free(thread->conns);
    free(thread->free_stack);
    free(thread->buffers);
    free(thread);
}

static int relay_pair(int fd_a, int fd_b, LureEpollStats* stats) {
    LureEpollThread temp;
    memset(&temp, 0, sizeof(temp));
    temp.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (temp.epoll_fd < 0) {
        return -1;
    }
    temp.buf_cap = 64 * 1024;  /* Increased from 16KB to reduce syscalls on high throughput */
    temp.done_fd = -1;
    temp.panic_on_error = lure_should_panic();

    LureConn conn;
    uint8_t* buf = (uint8_t*)calloc(temp.buf_cap * 2, 1);
    if (!buf) {
        close(temp.epoll_fd);
        return -1;
    }
    conn_init(&temp, &conn, fd_a, fd_b, 0, buf, buf + temp.buf_cap);
    temp.conns = &conn;

    set_nonblocking(fd_a);
    set_nonblocking(fd_b);
    set_tcp_opts(fd_a);
    set_tcp_opts(fd_b);

    conn.a_read = 1;
    conn.b_read = 1;
    conn.a_write = 0;
    conn.b_write = 0;
    epoll_add(temp.epoll_fd, fd_a, 0, LURE_EPOLL_SIDE_A, build_events(1, 0));
    epoll_add(temp.epoll_fd, fd_b, 0, LURE_EPOLL_SIDE_B, build_events(1, 0));

    struct epoll_event events[64];
    for (;;) {
        int n = epoll_wait(temp.epoll_fd, events, 64, -1);  /* No timeout for relay_pair - it's synchronous */
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            lure_panic_if(&temp, 1);
            break;
        }
        for (int i = 0; i < n; ++i) {
            uint64_t key = events[i].data.u64;
            uint32_t idx = 0;
            uint32_t side = 0;
            unpack_key(key, &idx, &side);
            uint32_t ev = events[i].events;
            if (ev & (EPOLLERR | EPOLLHUP)) {
                int saved_errno = errno;
                if (stats) {
                    *stats = conn.stats;
                }
                free(buf);
                close(temp.epoll_fd);
                lure_panic_if(&temp, 1);
                return saved_errno != 0 ? -saved_errno : -1;
            }
            if (ev & EPOLLIN) {
                handle_read(&temp, 0, side);
            }
            if (ev & EPOLLOUT) {
                flush_buf(&temp, 0, side);
            }
            if (conn.fd_a < 0 && conn.fd_b < 0) {
                free(buf);
                close(temp.epoll_fd);
                if (stats) {
                    *stats = conn.stats;
                }
                return -errno;
            }
            if ((conn.a_eof && conn.b_eof) && buf_avail(&conn.a2b) == 0 && buf_avail(&conn.b2a) == 0) {
                if (stats) {
                    *stats = conn.stats;
                }
                free(buf);
                close(temp.epoll_fd);
                return 0;
            }
        }
    }

    close(fd_a);
    close(fd_b);
    free(buf);
    close(temp.epoll_fd);
    if (stats) {
        *stats = conn.stats;
    }
    return -1;
}

int lure_epoll_passthrough(int fd_a, int fd_b, LureEpollStats* stats) {
    return relay_pair(fd_a, fd_b, stats);
}
