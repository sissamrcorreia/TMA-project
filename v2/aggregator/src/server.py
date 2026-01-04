"""
Central Aggregator Service
==========================

This service collects telemetry from distributed Agents via UDP and exposes
metrics via both HTTP (Prometheus) and WebSocket (Real-time Dashboard).
It uses a Hierarchical Heavy Hitter (HHH) Trie to aggregate traffic flows.
"""

import eventlet
eventlet.monkey_patch()

import os
import json
import socket
import threading
from flask import Flask, jsonify
from flask_socketio import SocketIO
from hhhtrie import HHHTrie
from prometheus_client import make_wsgi_app, Counter, Gauge
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# --- Configuration Constants ---
UDP_IP = "0.0.0.0"
UDP_PORT = 5005
HTTP_PORT = 8080
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", 100))

# Initialize Content Structures
hhh_analyzer = HHHTrie()
app = Flask(__name__)
# Initialize SocketIO (Async via Eventlet)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- PROMETHEUS METRICS DEFINITIONS ---
TOTAL_BYTES = Counter('tma_throughput_bytes_total', 'Total bytes received by aggregator')
AGENT_CPU = Gauge('tma_agent_cpu_usage', 'Current CPU usage of agent', ['agent_ip'])
HEAVY_HITTER_BYTES = Counter('tma_heavy_hitter_bytes_total', 'Bytes consumed by heavy hitter prefix', ['dest_ip'])

# Restored Metrics (for Legacy Dashboards)
PROTOCOL_BYTES = Counter('tma_protocol_bytes_total', 'Bytes by Protocol', ['protocol'])
PORT_BYTES = Counter('tma_port_bytes_total', 'Bytes by Destination Port', ['port'])

# New HLL Metrics
HLL_UNIQUE_FLOWS = Gauge('tma_hll_unique_flows', 'Estimated Unique 5-Tuple Flows', ['agent_ip'])
HLL_UNIQUE_SRC_IPS = Gauge('tma_hll_unique_src_ips', 'Estimated Unique Source IPs', ['agent_ip'])

# Mount Prometheus WSGI app on /metrics
app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
    '/metrics': make_wsgi_app()
})

# Global State
AGENT_CPUS = {}

@socketio.on('connect')
def handle_connect():
    print("Client connected to WebSocket!")

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Returns Heavy Hitter analysis and system health via HTTP.
    Used for legacy polling or external health checks.
    """
    global AGENT_CPUS
    current_max_cpu = max(AGENT_CPUS.values()) if AGENT_CPUS else 0.0
    hitters = hhh_analyzer.get_heavy_hitters(ALERT_THRESHOLD)
    return jsonify({
        "threshold": ALERT_THRESHOLD,
        "heavy_hitters": hitters,
        "max_agent_cpu": current_max_cpu,
        "active_agents": len(AGENT_CPUS)
    })

def udp_listener():
    """
    Background Thread: Listens for UDP telemetry.
    
    Receives JSON payloads from agents, updates Prometheus metrics, 
    inserts flow data into the HHH Trie, and emits real-time events via WebSockets.
    """
    global AGENT_CPUS
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"UDP Listener running on {UDP_PORT}. Threshold: {ALERT_THRESHOLD} bytes.")

    while True:
        data, addr = sock.recvfrom(65535)
        agent_ip = addr[0]
        try:
            payload = json.loads(data.decode())
            
            # 1. Parse Agent 2.0 Payload
            cpu = payload.get("agent_cpu", 0.0)
            cms_data = payload.get("cms", {})
            hll_data = payload.get("hll", {})
            hll_summary = hll_data.get("summary", {})
            hll_cards = hll_summary.get("cardinalities", {})
            
            # Agent CPU Tracking
            AGENT_CPUS[agent_ip] = cpu
            AGENT_CPU.labels(agent_ip=agent_ip).set(cpu)
            
            # Update HLL Metrics
            unique_flows = hll_cards.get("unique_flows", 0)
            unique_srcs = hll_cards.get("unique_src_ips", 0)
            HLL_UNIQUE_FLOWS.labels(agent_ip=agent_ip).set(unique_flows)
            HLL_UNIQUE_SRC_IPS.labels(agent_ip=agent_ip).set(unique_srcs)
            
            # 2. Extract Flows for Trie (from CMS Heavy Hitters)
            # The agent sends { "src_ip":..., "dst_ip":..., "bytes":... }
            hh_list = cms_data.get("heavy_hitters_bytes", [])
            
            trie_inserted_count = 0
            batch_total_bytes = 0
            
            for flow in hh_list:
                dst_ip = flow.get("dst_ip")
                byte_count = flow.get("bytes", 0)
                proto = flow.get("proto", "UNKNOWN")
                dst_port = flow.get("dst_port", 0)
                
                batch_total_bytes += byte_count
                
                if dst_ip and byte_count > 0:
                    hhh_analyzer.insert(dst_ip, byte_count)
                    TOTAL_BYTES.inc(byte_count)
                    HEAVY_HITTER_BYTES.labels(dest_ip=dst_ip).inc(byte_count)
                    
                    # Restored Metrics Updates
                    PROTOCOL_BYTES.labels(protocol=str(proto)).inc(byte_count)
                    PORT_BYTES.labels(port=str(dst_port)).inc(byte_count)
                    
                    trie_inserted_count += 1
            
            if trie_inserted_count > 0:
                print(f"DEBUG: Inserted {trie_inserted_count} top flows into Trie from {agent_ip}")

            # 3. Aggregation (Trie)
            # Get the Hierarchical Heavy Hitters for the Icicle Chart
            icicle_hitters = hhh_analyzer.get_heavy_hitters(ALERT_THRESHOLD)

            # 4. Construct WebSocket Payload
            socket_payload = {
                "agent_ip": agent_ip,
                "agent_cpu": cpu,
                "total_bytes_delta": batch_total_bytes,
                "heavy_hitters": icicle_hitters, # For Icicle Chart
                "cms": cms_data,                 # For detailed Tables
                "hll": hll_data                  # For Stats
            }
            
            # 5. Emit
            socketio.emit('traffic_data', socket_payload)

        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    # Start UDP listener in background thread
    t = threading.Thread(target=udp_listener, daemon=True)
    t.start()

    # Start SocketIO Server (wraps Flask)
    print(f"SocketIO + HTTP API running on port {HTTP_PORT}...")
    socketio.run(app, host='0.0.0.0', port=HTTP_PORT)