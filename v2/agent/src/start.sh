#!/bin/bash
# -----------------------------------------------------------------------------
# Agent Startup Script
# -----------------------------------------------------------------------------
# This script prepares the environment for the eBPF agent. It:
# 1. Mounts necessary filesystems (debugfs, bpffs)
# 2. Loads and pins the eBPF program to the Traffic Control (TC) hook
# 3. Loads and attaches an XDP program for mitigation (manual policy)
# 4. Starts the user-space Python agent and background traffic controller
# -----------------------------------------------------------------------------

set -e

# 1. Mount DebugFS (Required for eBPF)
echo "🚀 Preparing eBPF environment..."
# Ensure DebugFS is mounted
if ! mount | grep -q "/sys/kernel/debug"; then
    mount -t debugfs debugfs /sys/kernel/debug
fi

# Ensure BPF FS is mounted (Critical for pinning)
if ! mount | grep -q "/sys/fs/bpf"; then
    echo "Mounting bpffs..."
    mount -t bpf bpf /sys/fs/bpf
fi

echo "🚀 Loading eBPF program with bpftool..."

# 1. Clean up previous (if any)
tc qdisc del dev eth0 clsact 2> /dev/null || true
rm -f /sys/fs/bpf/traffic_metrics_map 2> /dev/null || true
rm -f /sys/fs/bpf/traffic_prog 2> /dev/null || true

# XDP mitigation cleanup (if any)
rm -f /sys/fs/bpf/xdp_block_prog 2> /dev/null || true
rm -f /sys/fs/bpf/blocked_ipv4 2> /dev/null || true
rm -f /sys/fs/bpf/drops_total 2> /dev/null || true

# 2. Load the program
# We load the .o file. We pin ALL maps to /sys/fs/bpf so we don't care about internal name matching.
echo "Running: bpftool prog load /app/src/traffic.bpf.o ..."

if bpftool prog load /app/src/traffic.bpf.o /sys/fs/bpf/traffic_prog type classifier \
    pinmaps /sys/fs/bpf; then
    echo "✅ Program loaded and maps pinned."
    echo "Files in /sys/fs/bpf:"
    ls -l /sys/fs/bpf
else
    echo "❌ ERROR: Failed to load BPF program."
    echo "Debug Info:"
    ls -l /app/src/traffic.bpf.o
    mount | grep bpf
    exit 1
fi

# 3.1. Load XDP mitigation program (manual blocking via dashboard)
echo "🚧 Loading XDP mitigation program..."

if bpftool prog load /app/src/xdp_block.bpf.o /sys/fs/bpf/xdp_block_prog type xdp \
    pinmaps /sys/fs/bpf; then
    echo "✅ XDP program loaded and maps pinned."
else
    echo "⚠️  WARNING: Failed to load XDP program. Mitigation features will be unavailable."
fi

# 3.2. Attach to TC Egress (ALL Interfaces)
echo "Attaching to TC on all eth+ interfaces..."

# Loop through all ethernet interfaces
for iface_path in /sys/class/net/eth*; do
    iface=$(basename "$iface_path")
    echo " -> Processing interface: $iface"
    
    # Clean up old qdisc
    tc qdisc del dev $iface clsact 2> /dev/null || true
    
    # Create new clsact qdisc
    tc qdisc add dev $iface clsact
    
    # Attach the pinned BPF program
    if tc filter add dev $iface egress bpf object-pinned /sys/fs/bpf/traffic_prog direct-action; then
        echo "    ✅ Attached to $iface"
    else
        echo "    ❌ ERROR: Failed to attach to $iface"
    fi
done


# Attach XDP on all eth+ interfaces (INGRESS protection)
echo "Attaching XDP on all eth+ interfaces..."

for iface_path in /sys/class/net/eth*; do
    iface=$(basename "$iface_path")
    echo " -> XDP attach: $iface"

    ip link set dev "$iface" xdp off 2> /dev/null || true

    if [ -e /sys/fs/bpf/xdp_block_prog ]; then
        if ip link set dev "$iface" xdp pinned /sys/fs/bpf/xdp_block_prog; then
            echo "    ✅ XDP attached to $iface"
        else
            echo "    ⚠️  WARNING: Failed to attach XDP to $iface"
        fi
    else
        echo "    ⚠️  Skipping XDP attach (program not loaded)"
    fi
done

echo "✅ eBPF Loaded and Attached!"

# 2. Generate Background Traffic
echo "🔥 Starting Service logic..."

# A. ALWAYS be a Server (Receiver)
echo "Starting iperf3 Server..."
iperf3 -s --logfile /tmp/iperf_server.log &
touch /tmp/iperf_server.log

# B. ALWAYS run the Agent
echo "Starting Python Agent..."
python3 /app/src/agent.py &

# Wait for init
sleep 2

# C. If TARGETS defined, be a Client (Generator) too
# Check TARGET_HOSTS (plural) or TARGET_HOST (legacy)
TARGETS="${TARGET_HOSTS:-$TARGET_HOST}"

if [ ! -z "$TARGETS" ]; then
    echo "I am a CLIENT targeting: $TARGETS"
    
    # Start Controller (Manages iperf flows AND Normal Mode Noise)
    # This blocks, so it keeps container alive (or we wait)
    python3 /app/src/controller.py
else
    echo "No targets defined. Starting Controller in Passive/Noise Mode."
    # Even without targets, we run controller to generate noise
    python3 /app/src/controller.py
fi
