"""
Traffic Controller Service
==========================

This service acts as a traffic generator for load testing and simulation.
It can spawn multiple `iperf3` processes to target hosts and generates background
UDP noise to simulate realistic data center network activity.
"""

import subprocess
import os
import time
import threading
import socket
import random
import struct
from flask import Flask, jsonify, request

app = Flask(__name__)

# Global State
iperf_processes = []
# Define multiple targets to create "Realism" (Multiple Flows in Dashboard)
TARGETS = os.getenv("TARGET_HOSTS", "host-b,host-c,host-d").split(",")
CURRENT_MODE = "stopped"
NOISE_RUNNING = True

# XDP Mitigation / Policy Control
POLICY_TOKEN = os.getenv("TMA_POLICY_TOKEN", "")
BLOCKED_MAP_PATH = os.getenv("TMA_BLOCKED_MAP_PATH", "/sys/fs/bpf/blocked_ipv4")
DROPS_MAP_PATH = os.getenv("TMA_DROPS_MAP_PATH", "/sys/fs/bpf/drops_total")

def _require_token(req):
    if not POLICY_TOKEN:
        return True
    return req.headers.get("X-TMA-TOKEN", "") == POLICY_TOKEN

def _run(cmd, timeout=2.0):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def _ip_to_key_bytes(ip_str: str) -> bytes:
    # We want the u32 value 0xAC191405 to be stored as a u32 in host memory.
    # bpftool "key hex" for a u32 expects little-endian byte order.
    ip_u32 = struct.unpack("!I", socket.inet_aton(ip_str))[0]  # 0xAC191405
    return struct.pack("<I", ip_u32)  # bytes: 05 14 19 ac

def _key_bytes_to_ip(key_bytes: bytes) -> str:
    ip_u32 = struct.unpack("<I", key_bytes)[0]
    return socket.inet_ntoa(struct.pack("!I", ip_u32))

def _u64_to_le_bytes(v: int) -> bytes:
    return struct.pack("<Q", int(v) & 0xFFFFFFFFFFFFFFFF)

def _le_bytes_to_u64(b: bytes) -> int:
    return struct.unpack("<Q", b)[0]

def _bytes_to_bpftool_hex(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

def _bpftool_map_update_pinned(map_path: str, key_bytes: bytes, value_bytes: bytes) -> None:
    cmd = [
        "bpftool", "map", "update", "pinned", map_path,
        "key", "hex", *_bytes_to_bpftool_hex(key_bytes).split(),
        "value", "hex", *_bytes_to_bpftool_hex(value_bytes).split(),
    ]
    r = _run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"bpftool update failed: {r.stderr.strip() or r.stdout.strip()}")

def _bpftool_map_delete_pinned(map_path: str, key_bytes: bytes) -> None:
    cmd = [
        "bpftool", "map", "delete", "pinned", map_path,
        "key", "hex", *_bytes_to_bpftool_hex(key_bytes).split(),
    ]
    r = _run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"bpftool delete failed: {r.stderr.strip() or r.stdout.strip()}")

def _bpftool_map_dump_json(map_path: str):
    r = _run(["bpftool", "-j", "map", "dump", "pinned", map_path], timeout=3.0)
    if r.returncode != 0:
        raise RuntimeError(f"bpftool dump failed: {r.stderr.strip() or r.stdout.strip()}")
    import json
    return json.loads(r.stdout)

def _xdp_maps_available() -> bool:
    return os.path.exists(BLOCKED_MAP_PATH) and os.path.exists(DROPS_MAP_PATH)

def _bpftool_any_to_bytes(x):
    # case: list of ints
    if isinstance(x, list):
        if not x:
            return b""
        if isinstance(x[0], int):
            return bytes(x)
        # case: list of hex strings ("ac", "0xac", "AC")
        if isinstance(x[0], str):
            out = []
            for s in x:
                s = s.strip().lower()
                if s.startswith("0x"):
                    s = s[2:]
                out.append(int(s, 16))
            return bytes(out)

    # case: single hex string ("ac 19 0a 02")
    if isinstance(x, str):
        return bytes.fromhex(x)

    return b""

def simulate_noise():
    """
    Generates varied, low-volume background traffic to simulate a Data Center environment.
    
    Sends UDP packets to random IPs within the 10.0.x.x range. This ensures
    that the eBPF agent captures diverse "Active Flows" without requiring
    actual destination servers for every packet.
    """
    print("background noise generator started...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Internal DC Range simulation: 10.0.x.x
    while True:
        if CURRENT_MODE == "normal":
            try:
                # 1. Pick a random "Internal" IP
                octet_c = random.randint(0, 255)
                octet_d = random.randint(1, 254)
                target_ip = f"10.0.{octet_c}.{octet_d}"
                
                # 2. Send a small payload (DNS-like size or ACK size)
                payload = b"X" * random.randint(64, 512)
                sock.sendto(payload, (target_ip, 80))
                
                # 3. Varied Sleep (Bursty)
                time.sleep(random.uniform(0.05, 0.5)) 
            except Exception as e:
                print(f"Noise Error: {e}")
                time.sleep(1)
        else:
            # In Attack mode, we pause noise to devote resources to iperf?
            # Or keep it for realism. Let's pause to keep "Attack" signal clear.
            time.sleep(1)

def kill_all():
    global iperf_processes
    for p in iperf_processes:
        try:
            p.terminate()
            p.wait(timeout=1)
        except:
            p.kill()
    iperf_processes = []

def run_traffic(bandwidth=None):
    """
    Spawns iperf3 processes for EACH target host to generate high-volume traffic.

    Args:
        bandwidth (str, optional): The bandwidth limit for iperf3 (e.g., "1G"). 
                                   If None, runs at maximum speed.
    """
    global iperf_processes
    kill_all()
    
    for host in TARGETS:
        host = host.strip()
        if not host: continue
        
        cmd = ["iperf3", "-c", host, "-t", "0", "--forceflush"]
        if bandwidth:
            cmd.extend(["-b", bandwidth])
            
        print(f"Starting traffic to {host} (Bandwidth: {bandwidth or 'MAX'}): {' '.join(cmd)}")
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        iperf_processes.append(p)

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"mode": CURRENT_MODE, "targets": TARGETS, "active_processes": len(iperf_processes)})

@app.route('/start', methods=['POST'])
def start_attack():
    global CURRENT_MODE
    CURRENT_MODE = "attack"
    run_traffic(bandwidth=None) # MAX speed to all
    return jsonify({"message": f"Packet Storm Started to {TARGETS}", "mode": "attack"}), 200

@app.route('/stop', methods=['POST'])
def stop_attack():
    global CURRENT_MODE
    CURRENT_MODE = "normal"
    kill_all() # Stop iperf
    # Noise thread automatically resumes
    return jsonify({"message": "Traffic Normalized (Background Noise Only)", "mode": "normal"}), 200

# Policy API (Manual Mitigation MVP)
@app.route('/policy/status', methods=['GET'])
def policy_status():
    if not _xdp_maps_available():
        return jsonify({
            "xdp_ready": False,
            "error": "XDP maps not found. Check that xdp_block.bpf.o loaded and bpffs is mounted.",
        }), 200

    try:
        rules = []
        #now_ns = int(time.time() * 1e9)
        now_ns = time.monotonic_ns()

        entries = _bpftool_map_dump_json(BLOCKED_MAP_PATH)
        for e in entries:
            k = _bpftool_any_to_bytes(e.get("key", []))
            v = _bpftool_any_to_bytes(e.get("value", []))
            if len(k) != 4 or len(v) != 8:
                continue
            ip = _key_bytes_to_ip(k)
            expiry_ns = _le_bytes_to_u64(v)
            ttl_s = max(0.0, (expiry_ns - now_ns) / 1e9)
            if ttl_s <= 0:
                continue
            rules.append({
                "match": "src_ip",
                "ip": ip,
                "expires_in_s": round(ttl_s, 1),
            })
        drops_entries = _bpftool_map_dump_json(DROPS_MAP_PATH)
        drops_total = 0
        for e in drops_entries:
            k = _bpftool_any_to_bytes(e.get("key", []))
            if k != b"\x00\x00\x00\x00":
                continue
            v = _bpftool_any_to_bytes(e.get("value", []))
            if len(v) == 8:
                drops_total = _le_bytes_to_u64(v)

        return jsonify({
            "xdp_ready": True,
            "blocked_rules": sorted(rules, key=lambda r: r["expires_in_s"], reverse=True),
            "drops_total": drops_total,
        }), 200
    except Exception as e:
        return jsonify({"xdp_ready": False, "error": str(e)}), 200
    
@app.route('/policy/block', methods=['POST'])
def policy_block():
    if not _require_token(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if not _xdp_maps_available():
        return jsonify({"ok": False, "error": "xdp_not_ready"}), 400

    payload = request.get_json(force=True, silent=True) or {}
    ip = payload.get("ip", "")
    ttl_seconds = int(payload.get("ttl_seconds", 60))
    ttl_seconds = max(1, min(ttl_seconds, 3600))
    match = payload.get("match", "src_ip")
    if match != "src_ip":
        return jsonify({"ok": False, "error": "only src_ip supported in MVP"}), 400

    try:
        socket.inet_aton(ip)
    except Exception:
        return jsonify({"ok": False, "error": "invalid_ip"}), 400

    try:
        expiry_ns = time.monotonic_ns() + ttl_seconds * 1_000_000_000
        _bpftool_map_update_pinned(
            BLOCKED_MAP_PATH,
            _ip_to_key_bytes(ip),
            #_u64_to_le_bytes(1),
            _u64_to_le_bytes(expiry_ns),
        )
        return jsonify({
            "ok": True,
            "match": match,
            "ip": ip,
            "ttl_seconds": ttl_seconds,
        }), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    
@app.route('/policy/unblock', methods=['POST'])
def policy_unblock():
    if not _require_token(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if not _xdp_maps_available():
        return jsonify({"ok": False, "error": "xdp_not_ready"}), 400

    payload = request.get_json(force=True, silent=True) or {}
    ip = payload.get("ip", "")

    try:
        socket.inet_aton(ip)
    except Exception:
        return jsonify({"ok": False, "error": "invalid_ip"}), 400

    try:
        _bpftool_map_delete_pinned(BLOCKED_MAP_PATH, _ip_to_key_bytes(ip))
        return jsonify({"ok": True, "ip": ip}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

def initial_background_traffic():
    """Waits for system initialization before starting the background noise simulation thread."""
    time.sleep(5)
    print("Initializing Background Simulation...")
    
    # Start the Noise Thread
    noise_thread = threading.Thread(target=simulate_noise, daemon=True)
    noise_thread.start()

if __name__ == '__main__':
    print(f"Starting Agent Controller on port 5006. Targets: {TARGETS}")
    
    # Start background traffic thread
    t = threading.Thread(target=initial_background_traffic, daemon=True)
    t.start()
    
    app.run(host='0.0.0.0', port=5006)
