#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* Workload Trust States */
#define STATE_TRUSTED 0
#define STATE_SUSPECT 1
#define STATE_QUARANTINED 2

/* Shared Kernel-User Space eBPF Maps */
/* Key: Source IPv4 Address (__u32), Value: State (__u32) */
BPF_HASH(policy_map, u32, u32, 1024);

/* Per-IP dropped packet counter for observability */
BPF_HASH(drop_counter_map, u32, u64, 1024);

/* Diagnostic telemetry counters:
 * Index 0: Total frames intercepted by XDP
 * Index 1: IPv4 frames verified
 * Index 2: policy_map lookup hits
 * Index 3: Quarantined drops executed
 */
BPF_ARRAY(diagnostic_counters, u64, 4);

/* Last intercepted Source IP for verification */
BPF_ARRAY(last_intercepted_ip, u32, 1);

int xdp_static_filter(struct xdp_md *ctx) {
    int idx_total = 0, idx_ipv4 = 1, idx_hit = 2, idx_drop = 3;

    /* 0. Diagnostic: Record frame arrival */
    u64 *total = diagnostic_counters.lookup(&idx_total);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Parse Ethernet Frame Header & Enforce Verifier Bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Inspect only IPv4 packets; allow ARP and non-IPv4 control frames */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* Record IPv4 frame */
    u64 *ipv4_cnt = diagnostic_counters.lookup(&idx_ipv4);
    if (ipv4_cnt) {
        __sync_fetch_and_add(ipv4_cnt, 1);
    }

    /* 2. Parse IPv4 Header & Enforce Verifier Bounds */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    u32 src_ip = ip->saddr;

    /* Record last seen IP */
    int zero = 0;
    last_intercepted_ip.update(&zero, &src_ip);

    /* 3. O(1) Lookup in eBPF Policy Map */
    u32 *state = policy_map.lookup(&src_ip);
    if (state != NULL) {
        u64 *hit_cnt = diagnostic_counters.lookup(&idx_hit);
        if (hit_cnt) {
            __sync_fetch_and_add(hit_cnt, 1);
        }

        if (*state == STATE_QUARANTINED) {
            u64 *drop_cnt = diagnostic_counters.lookup(&idx_drop);
            if (drop_cnt) {
                __sync_fetch_and_add(drop_cnt, 1);
            }

            u64 zero_val = 0, *cnt;
            cnt = drop_counter_map.lookup_or_try_init(&src_ip, &zero_val);
            if (cnt) {
                __sync_fetch_and_add(cnt, 1);
            }
            /* Drop immediately at driver hook before sk_buff allocation */
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
