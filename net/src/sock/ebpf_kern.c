#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u32 sport;
    __u32 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u32);
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

SEC("sk_skb/stream_parser")
int lure_stream_parser(struct __sk_buff *skb)
{
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int lure_stream_verdict(struct __sk_buff *skb)
{
    struct sock_key key = {};
    struct loop_state st = {};
    long rc;

    st.limit = 4;
    rc = bpf_loop(st.limit, loop_accumulate, &st, 0);
    if (rc < 0) {
        return SK_DROP;
    }

    key.sip4 = skb->local_ip4;
    key.dip4 = skb->remote_ip4;
    key.sport = bpf_htonl(skb->local_port);
    key.dport = skb->remote_port;
    {
        long rc_redirect = bpf_sk_redirect_hash(skb, &lure_sockhash, &key, BPF_F_INGRESS);
        bpf_printk(
            "lure sk_skb sip=%x dip=%x sport=%x dport=%x rc=%d",
            key.sip4,
            key.dip4,
            key.sport,
            key.dport,
            (int)rc_redirect
        );
        return rc_redirect;
    }
}
