// -----------------------------------------------------------------------------
// TMA XDP Mitigation Program
// -----------------------------------------------------------------------------
// A minimal XDP program that can DROP packets based on a pinned policy map.
//
// MVP goal:
//   - Dashboard -> Agent Controller (/policy/block) -> update blocked_ipv4 map
//   - XDP checks src IPv4 against map, enforces TTL, drops if active
//
// Notes:
//   - Runs on INGRESS (XDP). Best for mitigating inbound DDoS/scans.
//   - TTL is enforced by storing an expiry timestamp (ns) in blocked_ipv4.
//   - A simple drops_total counter is exposed for the dashboard.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ip (network byte order bits) -> expiry_ns
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ipv4 SEC(".maps");

// Single global counter: total drops
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops_total SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *src_ip, __u32 *dst_ip) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;

    *src_ip = iph->saddr; // network byte order bits
    *dst_ip = iph->daddr; // network byte order bits
    return 1;
}

SEC("xdp")
int xdp_block(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 src_ip = 0, dst_ip = 0;
    if (!parse_ipv4(data, data_end, &src_ip, &dst_ip)) {
        return XDP_PASS;
    }

    // MVP policy: block by SRC IP.
    __u64 *expiry = bpf_map_lookup_elem(&blocked_ipv4, &src_ip);
    if (!expiry) {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    if (now > *expiry) {
        // Expired rule: allow traffic. Cleanup is handled in user-space.
        return XDP_PASS;
    }

    // Count drops
    __u32 k = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drops_total, &k);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }

    return XDP_DROP;
}
