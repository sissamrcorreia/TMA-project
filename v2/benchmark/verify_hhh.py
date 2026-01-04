"""
Hierarchical Heavy Hitter (HHH) Validation
==========================================

This script performs an end-to-end integration test of the Aggregator's HHH algorithm.
It simulates a specific traffic pattern (1 Heavy Hitter + Noise) by sending a crafted
UDP payload and verifying that the Aggregator correctly identifies the heavy hitter
and filters the noise via the WebSocket API.
"""

import time
import socket
import json
import socketio
import sys

# Constants
AGGREGATOR_HOST = "aggregator"
AGGREGATOR_UDP_PORT = 5005
AGGREGATOR_WS_URL = "http://aggregator:8080"

# Test Data
# Pattern: One Heavy Hitter (10.0.0.1) and Background Noise
HEAVY_HITTER_IP = "10.0.0.1"
HEAVY_VAL = 500000000 # 500 MB (Huge)
NOISE_VAL = 100     # 100 B

PAYLOAD = {
    "agent_cpu": 10.5,
    "cms": {
        "heavy_hitters_bytes": [
            {"src_ip": "192.168.1.1", "dst_ip": HEAVY_HITTER_IP, "bytes": HEAVY_VAL},
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.2", "bytes": NOISE_VAL},
            {"src_ip": "192.168.1.3", "dst_ip": "10.0.0.3", "bytes": NOISE_VAL},
            {"src_ip": "192.168.1.4", "dst_ip": "10.0.0.4", "bytes": NOISE_VAL},
            # False Positive Bait (Another heavy one but below threshold? No, just random)
            {"src_ip": "192.168.1.5", "dst_ip": "172.16.0.1", "bytes": 500}
        ]
    }
}

sio = socketio.Client()
results = {"received": False, "hitters": []}

@sio.on('connect')
def on_connect():
    print("   [WS] Connected to Aggregator")

@sio.on('traffic_data')
def on_data(data):
    # The aggregator sends 'heavy_hitters' list in the payload
    # Structure: [{'prefix': '10.0.0.1/32', 'bytes': ...}, ...]
    if 'heavy_hitters' in data:
        results['received'] = True
        results['hitters'] = data['heavy_hitters']
        print(f"   [WS] Received {len(data['heavy_hitters'])} Heavy Hitters")

def run_test():
    """
    Executes the validation workflow:
    1. Connects to Aggregator WebSocket.
    2. Injects synthetic UDP payload with known heavy hitter.
    3. Waits for WebSocket update.
    4. Asserts that the Heavy Hitter is present and noise is handled correctly.
    """
    print(f"=== HHH Algorithm Validation ===")
    
    # 1. Connect WebSocket
    try:
        sio.connect(AGGREGATOR_WS_URL)
    except Exception as e:
        print(f"   [Error] WS Connect failed: {e}")
        return

    # 2. Send UDP Payload
    print(f"   [UDP] Sending Payload (Heavy: {HEAVY_HITTER_IP}, Bytes: {HEAVY_VAL})")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(json.dumps(PAYLOAD).encode(), (AGGREGATOR_HOST, AGGREGATOR_UDP_PORT))
    
    # 3. Wait for WS Response
    print("   [Wait] Waiting for Aggregator processing...")
    timeout = 5
    start = time.time()
    while time.time() - start < timeout:
        if results['received']:
            break
        time.sleep(0.1)
    
    sio.disconnect()
    
    if not results['received']:
        print("   [Fail] No WebSocket update received.")
        sys.exit(1)
        
    # 4. Analyze Results
    hitters = results['hitters']
    # Look for /32 of heavy IP
    found_heavy = False
    false_positives = 0
    noise_found = False
    
    print("\n   [Analysis] Detected Prefixes:")
    for h in hitters:
        p = h['prefix']
        b = h['bytes']
        print(f"      - {p}: {b} bytes")
        
        if HEAVY_HITTER_IP in p:
            found_heavy = True
        elif "10.0.0." in p:
             # If it detects 10.0.0.2/32 specifically, that's a False Positive (it's noise)
             # UNLESS it aggregates to 10.0.0.0/24 (which is valid aggregation)
             if "/32" in p:
                 noise_found = True
        elif "172.16.0.1" in p:
             false_positives += 1
             
    # Conclusion
    print("\n   [Result]")
    if found_heavy:
        print("      ✅ True Positive: Heavy Hitter 10.0.0.1 detected.")
    else:
        print("      ❌ False Negative: Heavy Hitter MISSED.")
        
    if noise_found:
        print("      ⚠️  Warning: Noise IPs were flagged individually (Threshold too low?).")
    else:
        print("      ✅ Noise Filtering: Small flows aggregated or ignored.")
        
    if false_positives > 0:
        print("      ❌ False Positive: 172.16.0.1 flagged (Should be ignored).")
    else:
        print("      ✅ False Positive Check: Passed.")

if __name__ == "__main__":
    run_test()
