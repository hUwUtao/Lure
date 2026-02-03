#ifndef LURE_SOCK_EPOLL_H
#define LURE_SOCK_EPOLL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LureEpollThread LureEpollThread;

typedef struct {
    uint64_t c2s_bytes;
    uint64_t s2c_bytes;
    uint64_t c2s_chunks;
    uint64_t s2c_chunks;
} LureEpollStats;

typedef struct {
    int fd_a;
    int fd_b;
    uint64_t id;
} LureEpollCmd;

typedef struct {
    uint64_t id;
    LureEpollStats stats;
    int result;
} LureEpollDone;

LureEpollThread* lure_epoll_thread_new(int cmd_fd, int done_fd, size_t max_conns, size_t buf_cap);
int lure_epoll_thread_run(LureEpollThread* thread);
void lure_epoll_thread_shutdown(LureEpollThread* thread);
void lure_epoll_thread_free(LureEpollThread* thread);

int lure_epoll_passthrough(int fd_a, int fd_b, LureEpollStats* stats);

#ifdef __cplusplus
}
#endif

#endif
