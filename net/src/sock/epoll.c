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
};

typedef struct {
    uint8_t data[BUF_CAP];
    size_t off;
    size_t len;
} PendingBuf;

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

    int eof_a;
    int eof_b;
    int shut_wr_a;
    int shut_wr_b;
    PendingBuf a2b;
    PendingBuf b2a;
};

static inline void shared_set_flag(LureEpollShared* shared, uint32_t flag) {
    __atomic_fetch_or(&shared->state_flags, flag, __ATOMIC_RELEASE);
}

static inline void shared_clear_flag(LureEpollShared* shared, uint32_t flag) {
    __atomic_fetch_and(&shared->state_flags, ~flag, __ATOMIC_RELEASE);
}

static inline int shared_abort_requested(const LureEpollShared* shared) {
    return __atomic_load_n(&shared->abort_flag, __ATOMIC_ACQUIRE) != 0;
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
    uint32_t ev = EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if (side == SIDE_A) {
        if (!conn->eof_a && conn->a2b.len == conn->a2b.off) {
            ev |= EPOLLIN;
        }
        if (conn->b2a.len > conn->b2a.off) {
            ev |= EPOLLOUT;
        }
    } else {
        if (!conn->eof_b && conn->b2a.len == conn->b2a.off) {
            ev |= EPOLLIN;
        }
        if (conn->a2b.len > conn->a2b.off) {
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

static int refresh_interest(struct LureEpollConnection* conn) {
    if (epoll_mod(conn->epoll_fd, conn->shared->fd_a, SIDE_A, side_events(conn, SIDE_A)) < 0) {
        return -errno;
    }
    if (epoll_mod(conn->epoll_fd, conn->shared->fd_b, SIDE_B, side_events(conn, SIDE_B)) < 0) {
        return -errno;
    }
    return 0;
}

static inline int pending_flush(PendingBuf* pending, int out_fd, uint64_t* total_bytes) {
    while (pending->off < pending->len) {
        ssize_t n = write(out_fd, pending->data + pending->off, pending->len - pending->off);
        if (n > 0) {
            pending->off += (size_t)n;
            *total_bytes += (uint64_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            return 0;
        }
        return -errno;
    }

    pending->off = 0;
    pending->len = 0;
    return 0;
}

static int read_into_pending(int in_fd, PendingBuf* pending, uint64_t* chunks, int* reached_eof) {
    ssize_t n = read(in_fd, pending->data, sizeof(pending->data));
    if (n > 0) {
        pending->off = 0;
        pending->len = (size_t)n;
        *chunks += 1;
        return 0;
    }
    if (n == 0) {
        *reached_eof = 1;
        return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 0;
    }
    return -errno;
}

static inline int is_complete(const struct LureEpollConnection* conn) {
    return conn->eof_a && conn->eof_b &&
           conn->a2b.len == conn->a2b.off &&
           conn->b2a.len == conn->b2a.off;
}

static void* io_main(void* arg) {
    struct LureEpollConnection* conn = (struct LureEpollConnection*)arg;
    struct epoll_event events[MAX_EVENTS];

    for (;;) {
        if (shared_abort_requested(conn->shared)) {
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
                if ((ev & EPOLLIN) && !conn->eof_a && conn->a2b.len == conn->a2b.off) {
                    int rc = read_into_pending(
                        conn->shared->fd_a,
                        &conn->a2b,
                        &conn->shared->c2s_chunks,
                        &conn->eof_a
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                    rc = pending_flush(&conn->a2b, conn->shared->fd_b, &conn->shared->c2s_bytes);
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
                if (ev & EPOLLOUT) {
                    int rc = pending_flush(&conn->b2a, conn->shared->fd_a, &conn->shared->s2c_bytes);
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
            } else {
                if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn->eof_b = 1;
                }
                if ((ev & EPOLLIN) && !conn->eof_b && conn->b2a.len == conn->b2a.off) {
                    int rc = read_into_pending(
                        conn->shared->fd_b,
                        &conn->b2a,
                        &conn->shared->s2c_chunks,
                        &conn->eof_b
                    );
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                    rc = pending_flush(&conn->b2a, conn->shared->fd_a, &conn->shared->s2c_bytes);
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
                if (ev & EPOLLOUT) {
                    int rc = pending_flush(&conn->a2b, conn->shared->fd_b, &conn->shared->c2s_bytes);
                    if (rc < 0) {
                        conn->result = rc;
                        goto done;
                    }
                }
            }
        }

        if (conn->eof_a && !conn->shut_wr_b && conn->a2b.len == conn->a2b.off) {
            (void)shutdown(conn->shared->fd_b, SHUT_WR);
            conn->shut_wr_b = 1;
        }
        if (conn->eof_b && !conn->shut_wr_a && conn->b2a.len == conn->b2a.off) {
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
            __atomic_store_n(&conn->shared->abort_flag, 1u, __ATOMIC_RELEASE);
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
    shared->abort_flag = 0;
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
        __atomic_store_n(&conn->shared->abort_flag, 1u, __ATOMIC_RELEASE);
        (void)pthread_join(conn->io_thread, NULL);
        conn->io_started = 0;
    }

    if (conn->epoll_fd >= 0) {
        close(conn->epoll_fd);
        conn->epoll_fd = -1;
    }

    free(conn);
}
