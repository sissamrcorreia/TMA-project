#!/usr/bin/env python3
# Simple eBPF traffic monitor using BCC - works in any Kali/Ubuntu VM

from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack
import time

prog = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
};

struct flow_val_t {
    u64 bytes;
    u64 packets;
};

BPF_HASH(flows, struct flow_key_t, struct flow_val_t);

int trace_net(struct __sk_buff *skb) {
    u32 saddr = skb->remote_ip4;
    u32 daddr = skb->local_ip4;
    u16 sport = skb->remote_port;
    u16 dport = skb->local_port;
    u8 proto  = skb->protocol;

    struct flow_key_t key = {};
    key.saddr = saddr;
    key.daddr = daddr;
    key.sport = sport;
    key.dport = dport;
    key.proto = proto;

    struct flow_val_t *val, zero = {};
    val = flows.lookup_or_init(&key, &zero);
    val->bytes += skb->len;
    val->packets += 1;
    return 0;
}
"""

b = BPF(text=prog)
fn = b.load_func("trace_net", BPF.SCHED_CLS)

# attach to interface (change eth0 if needed)
iface = "eth0"
b.attach_tc(dev=iface, fn_name="trace_net", replace=True, attach_point="ingress")

print(f"Monitoring traffic on {iface}... Ctrl-C to stop.")

flows = b.get_table("flows")

try:
    while True:
        time.sleep(3)
        print("\nCurrent flows:")
        for k, v in flows.items():
            src = inet_ntop(AF_INET, pack("I", k.saddr))
            dst = inet_ntop(AF_INET, pack("I", k.daddr))
            print(f"{src}:{k.sport} -> {dst}:{k.dport} proto={k.proto} "
                  f"bytes={v.bytes} pkts={v.packets}")
except KeyboardInterrupt:
    print("Detaching...")
    b.remove_tc(dev=iface, attach_point="ingress")