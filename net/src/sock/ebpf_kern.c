#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, __u64);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lure_sockhash SEC(".maps");

struct loop_state {
    __u32 sum;
    __u32 limit;
};

static long loop_accumulate(__u32 idx, void *ctx)
{
    struct loop_state *st = ctx;
    st->sum += idx;
    return (idx + 1) >= st->limit;
}

SEC("sk_msg")
int lure_msg_verdict(struct sk_msg_md *msg)
{
    __u64 cookie = bpf_get_socket_cookie(msg);
    struct loop_state st = {};
    long rc;

    st.limit = 4;
    rc = bpf_loop(st.limit, loop_accumulate, &st, 0);
    if (rc < 0) {
        return SK_DROP;
    }

    /* If redirect fails, drop instead of leaking to userspace fallback path. */
    if (bpf_msg_redirect_hash(msg, &lure_sockhash, &cookie, BPF_F_INGRESS) == SK_PASS) {
        return SK_PASS;
    }
    return SK_DROP;
}
