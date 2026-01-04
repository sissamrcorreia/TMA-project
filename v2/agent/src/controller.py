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
from flask import Flask, jsonify, request

app = Flask(__name__)

# Global State
iperf_processes = []
# Define multiple targets to create "Realism" (Multiple Flows in Dashboard)
TARGETS = os.getenv("TARGET_HOSTS", "host-b,host-c,host-d").split(",")
CURRENT_MODE = "stopped"
NOISE_RUNNING = True

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
