#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Target protocol and option constants */
#define SOL_ALG 279
#define ALG_SET_KEY 1

#define SOL_UDP 17
#define UDP_ENCAP 100

#define SOL_RXRPC 278
#define RXRPC_SECURITY_KEY 1
#define RXRPC_MIN_SECURITY_LEVEL 2

/* Burst configuration: 4 calls within 1 second */
#define BURST_THRESHOLD 4
#define BURST_WINDOW_NS 1000000000ULL 

struct track_state {
    u64 last_ts;
    u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct track_state);
} exploit_state SEC(".maps");

SEC("lsm/socket_setsockopt")
int BPF_PROG(fuse_setsockopt, struct socket *sock, int level, int optname)
{
    /* Check if the syscall matches our target primitives */
    int is_copyfail = (level == SOL_ALG && optname == ALG_SET_KEY);
    int is_dirtyfrag_udp = (level == SOL_UDP && optname == UDP_ENCAP);
    int is_dirtyfrag_rx = (level == SOL_RXRPC && 
                           (optname == RXRPC_SECURITY_KEY || optname == RXRPC_MIN_SECURITY_LEVEL));

    /* Ignore irrelevant socket options to minimize overhead */
    if (!is_copyfail && !is_dirtyfrag_udp && !is_dirtyfrag_rx) {
        return 0;
    }

    /* Use process group ID (tgid) to catch threaded exploit variations */
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();

    struct track_state *state = bpf_map_lookup_elem(&exploit_state, &tgid);
    if (!state) {
        struct track_state init = { .last_ts = now, .count = 1 };
        bpf_map_update_elem(&exploit_state, &tgid, &init, BPF_ANY);
        return 0; /* Allow first setup call */
    }

    if (now - state->last_ts > BURST_WINDOW_NS) {
        /* Time window expired, reset the burst counter */
        state->count = 1;
        state->last_ts = now;
        return 0; /* Allow */
    }

    /* Inside the burst window, increment counter. 
     * Using atomic add prevents race conditions from multi-threaded attackers. */
    __sync_fetch_and_add(&state->count, 1);
    state->last_ts = now;

    if (state->count >= BURST_THRESHOLD) {
        bpf_printk("copyfrag-fuse: exploit burst blocked for tgid %d\n", tgid);
        return -1; /* -EPERM (Operation not permitted) */
    }

    return 0; /* Allow normal traffic */
}

char LICENSE[] SEC("license") = "GPL";
