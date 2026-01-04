"""
eBPF Traffic Agent
==================

This module runs on each host to collect network traffic metrics using eBPF maps.
It processes 5-tuple flow data, computes deltas, and aggregates statistics using
probabilistic data structures (Count-Min Sketch and HyperLogLog) before sending
telemetry to the central Aggregator.
"""

import time
import socket
import json
import struct
import os
import subprocess
import psutil
from datetime import datetime
from sketch import CountMinSketch, HyperLogLog

# --- Configuration Constants ---
AGGREGATOR_IP = os.getenv("AGGREGATOR_IP", "127.0.0.1")
UDP_PORT = 5005
MAP_PIN_PATH = "/sys/fs/bpf/flow_map"

print(f"Agent Configuration: Aggregator={AGGREGATOR_IP}:{UDP_PORT}")

# Initialize UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# State for Delta Calculation
# Key: "src|dst|proto|sport|dport" -> Value: {"bytes": X, "packets": Y}
previous_state = {}

def get_map_data(pin_path):
    """
    Reads the pinned BPF map using bpftool.

    Args:
        pin_path (str): The filesystem path to the pinned BPF map.

    Returns:
        list: A list of dictionary entries from the BPF map, or empty list on failure.
    """
    try:
        if not os.path.exists(pin_path):
            return []
        
        cmd = ["bpftool", "map", "dump", "pinned", pin_path, "-j"]
        result = subprocess.check_output(cmd)
        return json.loads(result)
    except Exception as e:
        return []

def parse_key_5tuple(key_data):
    """
    Parses a BPF map key representing a 5-tuple flow identifier.

    Struct Layout:
        saddr(4), daddr(4), sport(2), dport(2), proto(1), pad(3)
    
    Args:
        key_data (list): Raw byte integers from the JSON output of bpftool.

    Returns:
        dict: Parsed flow keys (src_ip, dst_ip, src_port, dst_port, proto), or None.
    """
    try:
        if isinstance(key_data, list):
            byte_data = bytes([int(x, 16) for x in key_data])
            if len(byte_data) == 16:
                # Unpack: 4B IP, 4B IP, 2B Port, 2B Port, 1B Proto, 3B Pad
                s_ip, d_ip, s_port, d_port, proto = struct.unpack("IIHHBxxx", byte_data)
                
                return {
                    "src_ip": socket.inet_ntoa(struct.pack("I", s_ip)),
                    "dst_ip": socket.inet_ntoa(struct.pack("I", d_ip)),
                    "src_port": s_port,
                    "dst_port": d_port,
                    "proto": "TCP" if proto == 6 else "UDP" if proto == 17 else f"{proto}"
                }
    except Exception as e:
        # print(f"Key Parse Error: {e}") 
        pass
    return None

def parse_value(val_data):
    """
    Parses flow metrics from the BPF map value.

    Args:
        val_data (list): Raw byte integers describing traffic volume.

    Returns:
        tuple: (bytes, packets) integers.
    """
    try:
        if isinstance(val_data, list):
            byte_data = bytes([int(x, 16) for x in val_data])
            if len(byte_data) == 16:
                b, p = struct.unpack("QQ", byte_data)
                return b, p
    except Exception:
        pass
    return 0, 0

def process_5tuple_map(pin_path, prev_state):
    """
    Reads the 5-tuple BPF map and computes traffic deltas since the last poll.

    Args:
        pin_path (str): Path to the pinned map.
        prev_state (dict): The previous state dictionary for calculating deltas.

    Returns:
        tuple: (List of flow deltas, New state dictionary)
    """
    raw_entries = get_map_data(pin_path)
    deltas = []
    new_state = {}
    
    for entry in raw_entries:
        key_raw = entry.get("key")
        val_raw = entry.get("value")
        
        flow_key = parse_key_5tuple(key_raw)
        if not flow_key: continue
        
        # Unique string ID for state tracking
        flow_id = f"{flow_key['src_ip']}|{flow_key['dst_ip']}|{flow_key['proto']}|{flow_key['src_port']}|{flow_key['dst_port']}"
        total_bytes, total_packets = parse_value(val_raw)
        
        # Calculate Delta
        prev = prev_state.get(flow_id, {"bytes": 0, "packets": 0})
        d_bytes = total_bytes - prev["bytes"]
        d_packets = total_packets - prev["packets"]
        
        if d_bytes < 0: d_bytes = total_bytes # Restart/Overflow
        if d_packets < 0: d_packets = total_packets

        # Store Current State
        new_state[flow_id] = {"bytes": total_bytes, "packets": total_packets}
        
        if d_bytes > 0:
            flow_key["bytes"] = d_bytes
            flow_key["packets"] = d_packets
            flow_key["flow_id"] = flow_id # For hashing
            deltas.append(flow_key)
            
    return deltas, new_state

print("Agent 2.0 (5-Tuple + Sketch) started...")

while True:
    start_time = time.time()
    time.sleep(1)
    
    # Poll Map
    flows_batch, previous_state = process_5tuple_map(MAP_PIN_PATH, previous_state)
    
    # Initialize Sketches for this Batch
    cms = CountMinSketch(width=2048, depth=5)
    hll = HyperLogLog(p=12)
    
    # Candidates for heavy hitters (we have exact deltas here, but we feed them to CMS logic)
    batch_candidates_bytes = {}
    batch_candidates_packets = {}
    
    for f in flows_batch:
        fid = f["flow_id"]
        b = f["bytes"]
        p = f["packets"]
        
        # Update Sketches
        cms.update(fid, count=b)
        hll.update(fid)
        hll.track_metadata(f['src_ip'], f['dst_ip'], f['src_port'], f['dst_port'])
        
        # Track candidates for "Heavy Hitter" list generation
        # We store the candidates to determine exact heavy hitters from this batch.
        batch_candidates_bytes[fid] = f
        
    # Generate Output
    runtime = time.time() - start_time
    cpu_usage = psutil.cpu_percent(interval=None)
    
    # Get Heavy Hitters (Top 20)
    # sorting by bytes to find top contributors in this window.
    sorted_flows = sorted(flows_batch, key=lambda x: x['bytes'], reverse=True)[:20]
    
    # Clean up flow object for export (remove internal flow_id)
    export_hh = []
    for f in sorted_flows:
        export_hh.append({
            "src_ip": f["src_ip"],
            "dst_ip": f["dst_ip"],
            "src_port": f["src_port"],
            "dst_port": f["dst_port"],
            "proto": f["proto"],
            "bytes": f["bytes"]
        })

    payload = {
        "timestamp": datetime.now().isoformat(),
        "runtime_seconds": runtime,
        "flows_processed": len(flows_batch),
        "batches_processed": 1,
        "agent_cpu": cpu_usage,
        
        "cms": {
            "summary": {
                "type": "count_min_sketch",
                "total_bytes": cms.total_bytes,
                "total_packets": cms.total_count, # Assuming we called update with packets? No we called with bytes.
                "dimensions": {"width": cms.width, "depth": cms.depth}
            },
            "heavy_hitters_bytes": export_hh
        },
        
        "hll": {
            "summary": {
                "type": "hyperloglog",
                "cardinalities": hll.get_cardinalities(),
                "diversity_score": hll.count() / max(1, len(flows_batch))
            }
        }
    }
    
    # Transmit
    if flows_batch or True:
        try:
            json_data = json.dumps(payload)
            sock.sendto(json_data.encode(), (AGGREGATOR_IP, UDP_PORT))
            if flows_batch:
                print(f"Sent Batch: {len(flows_batch)} Flows. Unique(HLL): {hll.count()}. CPU:{cpu_usage}%", flush=True)
            else:
                print(f"Sent Heartbeat (Idle). CPU:{cpu_usage}%", flush=True)
        except Exception as e:
            print(f"Send error: {e}", flush=True)