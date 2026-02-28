#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "epoll.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    SIDE_A = 0,
    SIDE_B = 1,
    MAX_EVENTS = 4,
    BUF_CAP = 64 * 1024,
    PIPE_CAP = 512 * 1024,  // Increased for sustained streaming
};

struct LureEpollConnection {
    LureEpollShared* shared;
    LureEpollStartupFailCb fail_cb;
    void* fail_cb_user;

    pthread_t io_thread;
    pthread_t cleanup_thread;
    int io_started;
    int cleanup_started;

    int epoll_fd;
    int result;
    uint32_t abort_flag;  // Moved from LureEpollShared (cache line 0)

    int eof_a;
    int eof_b;
    int shut_wr_a;
    int shut_wr_b;
    uint32_t prev_ev_a;  // Track previous interest mask to avoid unnecessary epoll_ctl
    uint32_t prev_ev_b;

    // Pipe pairs for splice (kernel-space forwarding, zero-copy)
    int a2b_pipe[2];     // [0] = read end, [1] = write end
    int b2a_pipe[2];
    size_t a2b_pipe_len; // Bytes currently buffered in pipe
    size_t b2a_pipe_len;
};

static inline void shared_set_flag(LureEpollShared* shared, uint32_t flag) {
    __atomic_fetch_or(&shared->state_flags, flag, __ATOMIC_RELEASE);
}

static inline void shared_clear_flag(LureEpollShared* shared, uint32_t flag) {
    __atomic_fetch_and(&shared->state_flags, ~flag, __ATOMIC_RELEASE);
}

static inline int conn_abort_requested(const struct LureEpollConnection* conn) {
    return __atomic_load_n(&conn->abort_flag, __ATOMIC_ACQUIRE) != 0;
}

static inline int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_opts(int fd) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
}

static inline uint32_t side_events(const struct LureEpollConnection* conn, int side) {
    uint32_t ev = EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;  // Always include EPOLLET for edge-triggered

    if (side == SIDE_A) {
        // EPOLLIN: read from A if pipe has room and no EOF
        if (!conn->eof_a && conn->a2b_pipe_len < PIPE_CAP) {
            ev |= EPOLLIN;
        }
        // EPOLLOUT: write to A if B→A pipe has data
        if (conn->b2a_pipe_len > 0) {
            ev |= EPOLLOUT;
        }
    } else {
        // EPOLLIN: read from B if pipe has room and no EOF
        if (!conn->eof_b && conn->b2a_pipe_len < PIPE_CAP) {
            ev |= EPOLLIN;
        }
        // EPOLLOUT: write to B if A→B pipe has data
        if (conn->a2b_pipe_len > 0) {
            ev |= EPOLLOUT;
        }
    }

    return ev;
}

static int epoll_mod(int epoll_fd, int fd, uint64_t key, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = key;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

// Splice data from src_fd into pipe, then drain pipe to dst_fd.
// Updates *pipe_len with residual bytes in pipe.
// Returns 0 on success, -errno on error, sets *eof if src closed.
static int splice_forward(int src_fd, int pipe_write, int pipe_read, int dst_fd,
                          size_t *pipe_len, int *eof)
{
    // Fill the pipe from src (only if pipe has room)
    if (*pipe_len < PIPE_CAP && !*eof) {
        ssize_t n = splice(src_fd, NULL, pipe_write, NULL,
                           PIPE_CAP - *pipe_len,
                           SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        if (n > 0) {
            *pipe_len += (size_t)n;
        } else if (n == 0) {
            *eof = 1;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -errno;
        }
    }

    // Drain pipe to dst (as much as possible)
    while (*pipe_len > 0) {
        ssize_t n = splice(pipe_read, NULL, dst_fd, NULL,
                           *pipe_len,
                           SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        if (n > 0) {
            *pipe_len -= (size_t)n;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;  // dst backpressure
        } else {
            return -errno;
        }
    }
    return 0;
}

static int refresh_interest(struct LureEpollConnection* conn) {
    uint32_t new_ev_a = side_events(conn, SIDE_A);
    uint32_t new_ev_b = side_events(conn, SIDE_B);

    // Only call epoll_ctl if the mask actually changed (reduces syscalls in steady state)
    if (new_ev_a != conn->prev_ev_a) {
        if (epoll_mod(conn->epoll_fd, conn->shared->fd_a, SIDE_A, new_ev_a) < 0) {
            return -errno;
        }
        conn->prev_ev_a = new_ev_a;
    }

    if (new_ev_b != conn->prev_ev_b) {
        if (epoll_mod(conn->epoll_fd, conn->shared->fd_b, SIDE_B, new_ev_b) < 0) {
            return -errno;
        }
        conn->prev_ev_b = new_ev_b;
    }

    return 0;
}

static inline int is_complete(const struct LureEpollConnection* conn) {
    // Complete when both sides closed and pipes are empty
    return conn->eof_a && conn->eof_b &&
           conn->a2b_pipe_len == 0 &&
           conn->b2a_pipe_len == 0;
}

static void* io_main(void* arg) {
    struct LureEpollConnection* conn = (struct LureEpollConnection*)arg;
    struct epoll_event events[MAX_EVENTS];

    for (;;) {
        if (conn_abort_requested(conn)) {
            conn->result = -ECANCELED;
            break;
        }

        int n = epoll_wait(conn->epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            conn->result = -errno;
            break;
        }

        for (int i = 0; i < n; i++) {
            uint32_t ev = events[i].events;
            uint64_t side = events[i].data.u64;

            if (side == SIDE_A) {
                if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn->eof_a = 1;
                }
                if (ev & EPOLLIN) {
                    // Splice from A into a2b pipe, then drain a2b pipe to B
                    int rc = splice_forward(
                        conn->shared->fd_a, conn->a2b_pipe[1], conn->a2b_pipe[0],
                        conn->shared->fd_b, &conn->a2b_pipe_len, &conn->eof_a
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                    conn->shared->c2s_bytes += 0;  // Spliced data counted at write endpoint
                    conn->shared->c2s_chunks += 1;
                }
                if (ev & EPOLLOUT) {
                    // Drain remaining b2a pipe data to A
                    while (conn->b2a_pipe_len > 0) {
                        ssize_t n = splice(conn->b2a_pipe[0], NULL, conn->shared->fd_a, NULL,
                                          conn->b2a_pipe_len, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
                        if (n > 0) {
                            conn->b2a_pipe_len -= (size_t)n;
                            conn->shared->s2c_bytes += (uint64_t)n;
                        } else {
                            break;  // backpressure
                        }
                    }
                }
            } else {
                if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn->eof_b = 1;
                }
                if (ev & EPOLLIN) {
                    // Splice from B into b2a pipe, then drain b2a pipe to A
                    int rc = splice_forward(
                        conn->shared->fd_b, conn->b2a_pipe[1], conn->b2a_pipe[0],
                        conn->shared->fd_a, &conn->b2a_pipe_len, &conn->eof_b
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                    conn->shared->s2c_bytes += 0;  // Spliced data counted at write endpoint
                    conn->shared->s2c_chunks += 1;
                }
                if (ev & EPOLLOUT) {
                    // Drain remaining a2b pipe data to B
                    while (conn->a2b_pipe_len > 0) {
                        ssize_t n = splice(conn->a2b_pipe[0], NULL, conn->shared->fd_b, NULL,
                                          conn->a2b_pipe_len, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
                        if (n > 0) {
                            conn->a2b_pipe_len -= (size_t)n;
                            conn->shared->c2s_bytes += (uint64_t)n;
                        } else {
                            break;  // backpressure
                        }
                    }
                }
            }
        }

        // Shutdown when one side closes and its outgoing pipe is empty
        if (conn->eof_a && !conn->shut_wr_b && conn->a2b_pipe_len == 0) {
            (void)shutdown(conn->shared->fd_b, SHUT_WR);
            conn->shut_wr_b = 1;
        }
        if (conn->eof_b && !conn->shut_wr_a && conn->b2a_pipe_len == 0) {
            (void)shutdown(conn->shared->fd_a, SHUT_WR);
            conn->shut_wr_a = 1;
        }

        int rc = refresh_interest(conn);
        if (rc < 0) {
            conn->result = rc;
            break;
        }

        if (is_complete(conn)) {
            conn->result = 0;
            break;
        }
    }

done:
    return NULL;
}

static void close_owned_fds(LureEpollShared* shared) {
    if (!shared) {
        return;
    }
    if (shared->fd_a >= 0) {
        close(shared->fd_a);
        shared->fd_a = -1;
    }
    if (shared->fd_b >= 0) {
        close(shared->fd_b);
        shared->fd_b = -1;
    }
}

static void* cleanup_main(void* arg) {
    struct LureEpollConnection* conn = (struct LureEpollConnection*)arg;

    if (conn->io_started) {
        (void)pthread_join(conn->io_thread, NULL);
        conn->io_started = 0;
    }

    if (conn->epoll_fd >= 0) {
        close(conn->epoll_fd);
        conn->epoll_fd = -1;
    }

    close_owned_fds(conn->shared);

    conn->shared->result = conn->result;
    shared_clear_flag(conn->shared, LURE_EPOLL_RUNNING);
    shared_set_flag(conn->shared, LURE_EPOLL_DONE);
    if (conn->result < 0) {
        shared_set_flag(conn->shared, LURE_EPOLL_FAILED);
    }

    return NULL;
}

static int startup_fail(
    LureEpollShared* shared,
    LureEpollStartupFailCb cb,
    void* cb_user,
    int err,
    struct LureEpollConnection* conn
) {
    if (shared) {
        shared->result = -err;
        shared_clear_flag(shared, LURE_EPOLL_RUNNING);
        shared_set_flag(shared, LURE_EPOLL_DONE | LURE_EPOLL_FAILED);
        close_owned_fds(shared);
    }

    if (conn) {
        if (conn->io_started) {
            __atomic_store_n(&conn->abort_flag, 1u, __ATOMIC_RELEASE);
            (void)pthread_join(conn->io_thread, NULL);
            conn->io_started = 0;
        }
        if (conn->epoll_fd >= 0) {
            close(conn->epoll_fd);
            conn->epoll_fd = -1;
        }
        free(conn);
    }

    if (cb) {
        cb(cb_user, err);
    }
    return -err;
}

int lure_epoll_connection_main(
    LureEpollShared* shared,
    LureEpollStartupFailCb on_startup_fail,
    void* user_data,
    LureEpollConnection** out_conn
) {
    if (!shared || !out_conn || shared->fd_a < 0 || shared->fd_b < 0) {
        return -EINVAL;
    }

    shared->c2s_bytes = 0;
    shared->s2c_bytes = 0;
    shared->c2s_chunks = 0;
    shared->s2c_chunks = 0;
    shared->result = 0;
    shared->state_flags = LURE_EPOLL_RUNNING;

    struct LureEpollConnection* conn =
        (struct LureEpollConnection*)calloc(1, sizeof(struct LureEpollConnection));
    if (!conn) {
        return startup_fail(shared, on_startup_fail, user_data, ENOMEM, NULL);
    }

    conn->shared = shared;
    conn->fail_cb = on_startup_fail;
    conn->fail_cb_user = user_data;
    conn->epoll_fd = -1;
    conn->a2b_pipe[0] = conn->a2b_pipe[1] = -1;
    conn->b2a_pipe[0] = conn->b2a_pipe[1] = -1;

    // Create pipes for zero-copy splice forwarding
    if (pipe2(conn->a2b_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }
    if (pipe2(conn->b2a_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    // Increase pipe capacity for sustained streaming (512KB per direction)
    (void)fcntl(conn->a2b_pipe[1], F_SETPIPE_SZ, PIPE_CAP);
    (void)fcntl(conn->b2a_pipe[1], F_SETPIPE_SZ, PIPE_CAP);

    if (set_nonblocking(shared->fd_a) < 0 || set_nonblocking(shared->fd_b) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    set_tcp_opts(shared->fd_a);
    set_tcp_opts(shared->fd_b);

    conn->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (conn->epoll_fd < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    ev.data.u64 = SIDE_A;
    if (epoll_ctl(conn->epoll_fd, EPOLL_CTL_ADD, shared->fd_a, &ev) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    ev.data.u64 = SIDE_B;
    if (epoll_ctl(conn->epoll_fd, EPOLL_CTL_ADD, shared->fd_b, &ev) < 0) {
        return startup_fail(shared, on_startup_fail, user_data, errno, conn);
    }

    // Initialize previous interest masks so refresh_interest() can detect changes (note: EPOLLET is always on)
    conn->prev_ev_a = EPOLLET | EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    conn->prev_ev_b = EPOLLET | EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    int rc = pthread_create(&conn->io_thread, NULL, io_main, conn);
    if (rc != 0) {
        return startup_fail(shared, on_startup_fail, user_data, rc, conn);
    }
    conn->io_started = 1;

    rc = pthread_create(&conn->cleanup_thread, NULL, cleanup_main, conn);
    if (rc != 0) {
        return startup_fail(shared, on_startup_fail, user_data, rc, conn);
    }
    conn->cleanup_started = 1;

    *out_conn = conn;
    return 0;
}

int lure_epoll_connection_join(LureEpollConnection* conn) {
    if (!conn) {
        return -EINVAL;
    }

    if (conn->cleanup_started) {
        int rc = pthread_join(conn->cleanup_thread, NULL);
        conn->cleanup_started = 0;
        if (rc != 0) {
            return -rc;
        }
    }

    return conn->result;
}

void lure_epoll_connection_free(LureEpollConnection* conn) {
    if (!conn) {
        return;
    }

    if (conn->cleanup_started) {
        (void)pthread_join(conn->cleanup_thread, NULL);
        conn->cleanup_started = 0;
    }

    if (conn->io_started) {
        __atomic_store_n(&conn->abort_flag, 1u, __ATOMIC_RELEASE);
        (void)pthread_join(conn->io_thread, NULL);
        conn->io_started = 0;
    }

    if (conn->epoll_fd >= 0) {
        close(conn->epoll_fd);
        conn->epoll_fd = -1;
    }

    // Close pipes
    if (conn->a2b_pipe[0] >= 0) {
        close(conn->a2b_pipe[0]);
        conn->a2b_pipe[0] = -1;
    }
    if (conn->a2b_pipe[1] >= 0) {
        close(conn->a2b_pipe[1]);
        conn->a2b_pipe[1] = -1;
    }
    if (conn->b2a_pipe[0] >= 0) {
        close(conn->b2a_pipe[0]);
        conn->b2a_pipe[0] = -1;
    }
    if (conn->b2a_pipe[1] >= 0) {
        close(conn->b2a_pipe[1]);
        conn->b2a_pipe[1] = -1;
    }

    free(conn);
}
