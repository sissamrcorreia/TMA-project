from bcc import BPF
import time
import ctypes as ct
import os

# Load eBPF program
# kernel_release = os.popen('uname -r').read().strip()
kernel_release = "6.16.8+kali-amd64" # Hardcoded, replace later TODO

# b = BPF(src_file="src/ebpf/flow_capture.bpf.c")
b = BPF(src_file="src/ebpf/flow_capture.bpf.c", cflags=[
    f"-I/usr/src/linux-headers-{kernel_release}/include/uapi",
    f"-I/usr/src/linux-headers-{kernel_release}/include",
    f"-I/usr/src/linux-headers-{kernel_release}/include/generated/uapi",
    f"-I/usr/src/linux-headers-{kernel_release}/include/generated",
    f"-I/usr/src/linux-headers-{kernel_release}/arch/x86/include",
    f"-I/usr/src/linux-headers-{kernel_release}/arch/x86/include/uapi",
    "-I/usr/include/bpf",
    "-D__TARGET_ARCH_x86"
])
b.attach_xdp(dev="eth0", fn=b.load_func("capture_flow", BPF.XDP))  # Replace eth0 with the interface you want to monitor

# Define structures matching eBPF
class FlowKey(ct.Structure):
    _fields_ = [
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("protocol", ct.c_uint8),
    ]

class FlowMetrics(ct.Structure):
    _fields_ = [
        ("bytes", ct.c_uint64),
        ("packets", ct.c_uint64),
        ("start_ts", ct.c_uint64),
    ]

flow_map = b["flow_map"]

def ip_to_str(ip):
    return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"

# Poll and print flows every 5 seconds
while True:
    print("\nCurrent Flows:")
    for k, v in flow_map.items():
        src_ip = ip_to_str(k.src_ip)
        dst_ip = ip_to_str(k.dst_ip)
        duration = (time.time_ns() - v.start_ts) / 1e9  # Approximate duration in seconds
        print(f"{src_ip}:{k.src_port} -> {dst_ip}:{k.dst_port} proto={k.protocol} | bytes={v.bytes} packets={v.packets} duration={duration:.2f}s")
    
    time.sleep(5)