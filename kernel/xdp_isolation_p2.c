#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

/* Workload Trust States */
#define STATE_TRUSTED 0
#define STATE_SUSPECT 1
#define STATE_QUARANTINED 2

/* TCP Flag Bitmasks */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* Wire-Speed Flow Telemetry Structure (32 bytes, 8-byte aligned) */
struct flow_event_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;
    u8  tcp_flags;
    u16 pkt_len;
    u32 state;
    u32 pad;
    u64 timestamp_ns;
};

/* Shared Kernel-User Space eBPF Maps */
/* Key: Source IPv4 Address (__u32), Value: Security State (__u32) */
BPF_HASH(policy_map, u32, u32, 1024);

/* Atomic packet counters per source IP */
BPF_HASH(drop_counter_map, u32, u64, 1024);
BPF_HASH(pass_counter_map, u32, u64, 1024);

/* Diagnostic telemetry counters:
 * Index 0: Total frames intercepted by XDP
 * Index 1: IPv4 frames verified
 * Index 2: TCP frames parsed
 * Index 3: UDP frames parsed
 * Index 4: Other L4 frames (e.g. ICMP)
 * Index 5: Trusted passes executed
 * Index 6: Suspect drops executed (SYN throttle or 50% drop)
 * Index 7: Quarantined drops executed
 */
BPF_ARRAY(diagnostic_counters, u64, 8);

/* Ring Buffer for Wire-Speed Flow Telemetry (256 pages = 1MB) */
BPF_RINGBUF_OUTPUT(telemetry_ringbuf, 256);

int xdp_dynamic_filter(struct xdp_md *ctx) {
    int idx_total = 0, idx_ipv4 = 1, idx_tcp = 2, idx_udp = 3, idx_other = 4;
    int idx_pass = 5, idx_suspect_drop = 6, idx_quarantine_drop = 7;

    /* 0. Diagnostic: Record frame arrival */
    u64 *total = diagnostic_counters.lookup(&idx_total);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Parse Ethernet Header & Enforce Verifier Bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Pass non-IPv4 traffic (ARP, ND, STP) to maintain L2 bridge topology */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    u64 *ipv4_cnt = diagnostic_counters.lookup(&idx_ipv4);
    if (ipv4_cnt) {
        __sync_fetch_and_add(ipv4_cnt, 1);
    }

    /* 2. Parse IPv4 Header & Enforce Verifier Bounds */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    /* Validate IPv4 header length (minimum 5 32-bit words = 20 bytes) */
    if (ip->ihl < 5) {
        return XDP_PASS;
    }

    /* Bound-check dynamic IPv4 header length for verifier safety */
    u32 ip_hdr_len = (ip->ihl & 0x0F) * 4;
    void *l4_hdr = (void *)ip + ip_hdr_len;
    if (l4_hdr > data_end) {
        return XDP_PASS;
    }

    u32 src_ip = ip->saddr;
    u32 dst_ip = ip->daddr;
    u8  protocol = ip->protocol;
    u16 src_port = 0;
    u16 dst_port = 0;
    u8  tcp_flags = 0;
    u16 pkt_len = (u16)(data_end - data);

    /* 3. Parse L4 Header (TCP / UDP) */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        /* TCP flags byte is byte 13 of the TCP header */
        tcp_flags = ((u8 *)tcp)[13];

        u64 *tcp_cnt = diagnostic_counters.lookup(&idx_tcp);
        if (tcp_cnt) {
            __sync_fetch_and_add(tcp_cnt, 1);
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)l4_hdr;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);

        u64 *udp_cnt = diagnostic_counters.lookup(&idx_udp);
        if (udp_cnt) {
            __sync_fetch_and_add(udp_cnt, 1);
        }
    } else {
        u64 *oth_cnt = diagnostic_counters.lookup(&idx_other);
        if (oth_cnt) {
            __sync_fetch_and_add(oth_cnt, 1);
        }
    }

    /* 4. O(1) Policy Map Lookup */
    u32 *st_ptr = policy_map.lookup(&src_ip);
    u32 current_state = st_ptr ? *st_ptr : STATE_TRUSTED;

    /* Build telemetry event */
    struct flow_event_t event = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
        .tcp_flags = tcp_flags,
        .pkt_len = pkt_len,
        .state = current_state,
        .pad = 0,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    /* 5. Multi-Tier Security Enforcement */

    /* Tier 2: Quarantined Workload (100% Wire-Speed Drop) */
    if (current_state == STATE_QUARANTINED) {
        u64 *qdrop_cnt = diagnostic_counters.lookup(&idx_quarantine_drop);
        if (qdrop_cnt) {
            __sync_fetch_and_add(qdrop_cnt, 1);
        }

        u64 zero_val = 0, *cnt;
        cnt = drop_counter_map.lookup_or_try_init(&src_ip, &zero_val);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }

        /* Sample 1 in 64 packets to ring buffer:
         * Prevents ring buffer saturation during volumetric DDoS,
         * while keeping user-space daemon aware that flood is continuing.
         */
        if ((bpf_get_prandom_u32() & 0x3F) == 0) {
            telemetry_ringbuf.ringbuf_output(&event, sizeof(event), 0);
        }

        /* Drop immediately at NIC driver before sk_buff memory allocation */
        return XDP_DROP;
    }

    /* Tier 1: Suspect Workload (Probabilistic Rate-Limit & SYN Suppression) */
    if (current_state == STATE_SUSPECT) {
        int drop_packet = 0;

        /* Suppress TCP SYN packets to halt connection exhaustion */
        if (protocol == IPPROTO_TCP && (tcp_flags & TCP_FLAG_SYN)) {
            drop_packet = 1;
        } else if ((bpf_get_prandom_u32() & 0x01) == 0) {
            /* Drop 50% random packets to protect victim capacity */
            drop_packet = 1;
        }

        /* Always stream telemetry for suspect flows */
        telemetry_ringbuf.ringbuf_output(&event, sizeof(event), 0);

        if (drop_packet) {
            u64 *sdrop_cnt = diagnostic_counters.lookup(&idx_suspect_drop);
            if (sdrop_cnt) {
                __sync_fetch_and_add(sdrop_cnt, 1);
            }
            u64 zero_val = 0, *cnt;
            cnt = drop_counter_map.lookup_or_try_init(&src_ip, &zero_val);
            if (cnt) {
                __sync_fetch_and_add(cnt, 1);
            }
            return XDP_DROP;
        } else {
            u64 *pass_cnt = diagnostic_counters.lookup(&idx_pass);
            if (pass_cnt) {
                __sync_fetch_and_add(pass_cnt, 1);
            }
            u64 zero_val = 0, *cnt;
            cnt = pass_counter_map.lookup_or_try_init(&src_ip, &zero_val);
            if (cnt) {
                __sync_fetch_and_add(cnt, 1);
            }
            return XDP_PASS;
        }
    }

    /* Tier 0: Trusted Workload (Default: Line-Rate Pass + Telemetry Stream) */
    u64 *pass_cnt = diagnostic_counters.lookup(&idx_pass);
    if (pass_cnt) {
        __sync_fetch_and_add(pass_cnt, 1);
    }

    u64 zero_val = 0, *cnt;
    cnt = pass_counter_map.lookup_or_try_init(&src_ip, &zero_val);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }

    /* Stream flow event to telemetry ring buffer */
    telemetry_ringbuf.ringbuf_output(&event, sizeof(event), 0);

    return XDP_PASS;
}
