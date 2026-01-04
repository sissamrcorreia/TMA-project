/*
 * eBPF Traffic Classifier
 * =======================
 *
 * This BPF program attaches to the Traffic Control (TC) egress hook to monitor
 * outgoing network packets. It extracts 5-tuple flow information (Source/Dest IP,
 * Source/Dest Port, Protocol) and aggregates byte/packet counts in a BPF Hash Map.
 */

// Manually define standard types to avoid system header dependency issues
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// Endian specific types (storage only, BPF treats as int)
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

// Little Endian types (needed by some headers)
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;

// Legacy checksum type
typedef __u16 __sum16;

// Aligned type used by bpf.h
typedef __u64 __aligned_u64;

// Prevent linux/types.h and related headers from being included and clashing
#define _LINUX_TYPES_H
#define _UAPI_LINUX_TYPES_H
#define _ASM_GENERIC_TYPES_H
#define _ASM_GENERIC_INT_LL64_H

// Now we can include bpf headers
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// 5-Tuple Key Structure
struct flow_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 proto;
  __u8 padding[3]; // Align to 4 bytes
};

// Flow Metrics (Value Structure)
struct flow_metrics {
  __u64 bytes;
  __u64 packets;
};

// Map: 5-Tuple -> Metrics
// Uses a Hash Map to store flow states.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct flow_key);
  __type(value, struct flow_metrics);
} flow_map SEC(".maps");

SEC("classifier")
int count_packets(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;

  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  // Initialize Key
  struct flow_key key = {};
  key.src_ip = ip->saddr;
  key.dst_ip = ip->daddr;
  key.proto = ip->protocol;

  // Header Parsing (Ports)
  __u32 ihl = ip->ihl * 4;
  if (ihl < sizeof(struct iphdr))
    return TC_ACT_OK;

  void *trans_hdr = (void *)ip + ihl;

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = trans_hdr;
    if ((void *)(tcp + 1) <= data_end) {
      key.src_port = bpf_ntohs(tcp->source);
      key.dst_port = bpf_ntohs(tcp->dest);
    }
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = trans_hdr;
    if ((void *)(udp + 1) <= data_end) {
      key.src_port = bpf_ntohs(udp->source);
      key.dst_port = bpf_ntohs(udp->dest);
    }
  }

  // Update Map
  struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_map, &key);
  if (metrics) {
    __sync_fetch_and_add(&metrics->bytes, skb->len);
    __sync_fetch_and_add(&metrics->packets, 1);
  } else {
    struct flow_metrics new_metrics = {.bytes = skb->len, .packets = 1};
    bpf_map_update_elem(&flow_map, &key, &new_metrics, BPF_ANY);
  }

  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";