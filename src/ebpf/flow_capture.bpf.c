#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Define the flow key (5-tuple)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// Define the flow metrics
struct flow_metrics {
    __u64 bytes;
    __u64 packets;
    __u64 start_ts;  // Timestamp of first packet
};

// BPF hash map to store flows (key: flow_key, value: flow_metrics)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
    __uint(max_entries, 1024);  // Start small; increase later
} flow_map SEC(".maps");

SEC("xdp")
int capture_flow(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;

    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
    };

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end) return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else {
        key.src_port = 0;
        key.dst_port = 0;
    }

    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_map, &key);
    if (metrics) {
        // Update existing flow
        __sync_fetch_and_add(&metrics->bytes, __builtin_bswap32(ip->tot_len));  // Bytes (network byte order)
        __sync_fetch_and_add(&metrics->packets, 1);
    } else {
        // New flow
        struct flow_metrics new_metrics = {
            .bytes = __builtin_bswap32(ip->tot_len),
            .packets = 1,
            .start_ts = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_map, &key, &new_metrics, BPF_ANY);
    }

    return XDP_PASS;  // Pass packet to stack; don't drop
}

char _license[] SEC("license") = "GPL";