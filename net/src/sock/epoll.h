#ifndef LURE_SOCK_EPOLL_H
#define LURE_SOCK_EPOLL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LureEpollConnection LureEpollConnection;

typedef struct {
    int fd_a;
    int fd_b;
    uint64_t c2s_bytes;
    uint64_t s2c_bytes;
    uint64_t c2s_chunks;
    uint64_t s2c_chunks;
    int32_t result;
    uint32_t state_flags;
    uint32_t abort_flag;
} LureEpollShared;

enum {
    LURE_EPOLL_RUNNING = 1u << 0,
    LURE_EPOLL_DONE = 1u << 1,
    LURE_EPOLL_FAILED = 1u << 2,
};

typedef void (*LureEpollStartupFailCb)(void* user_data, int err);

int lure_epoll_connection_main(
    LureEpollShared* shared,
    LureEpollStartupFailCb on_startup_fail,
    void* user_data,
    LureEpollConnection** out_conn
);

int lure_epoll_connection_join(LureEpollConnection* conn);
void lure_epoll_connection_free(LureEpollConnection* conn);

#ifdef __cplusplus
}
#endif

#endif
