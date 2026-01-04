# Decentralized Flow Monitoring System
## Setup and Execution Guide

---

## 📁 Project Structure

Create the following directory structure:

```
src/
├── capture/
│   ├── flow_capture_json.c          # Already provided
├── aggregation/
│   ├── __init__.py                 # Empty file
│   ├── cms_aggregator.py           # Count-Min Sketch
│   ├── hll_aggregator.py           # HyperLogLog
│   └── file_aggregation_engine.py  # Main engine
├── output/
│   ├── aggregated_flows/           # Auto-created
|   └── flows/                      # json of the actual flows (auto created)
├── requirements.txt
├── run_system.sh
└── README.md
```

---

## 🔧 Installation

### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libpcap-dev gcc python3 python3-pip
```

**CentOS/RHEL:**
```bash
sudo yum install libpcap-devel gcc python3 python3-pip
```

**macOS:**
```bash
brew install libpcap
```

### Step 2: Make Scripts Executable

```bash
chmod +x run_system.sh
chmod +x aggregation/file_aggregation_engine.py
```

### Step 3: Compile Capture Program (done in run_system.sh)

```bash
cd capture
gcc -o flow_capture_json flow_capture_json.c -lpcap
cd ..
```

---

## 🚀 Execution

### Option 1: Quick Start (Recommended)

```bash
# Run with auto-detected interface
sudo ./run_system.sh

# Run with specific interface
sudo ./run_system.sh eth0

# Custom configuration
sudo ./run_system.sh --interface wlan0 --export-interval 30
```

### Option 2: Background Service

```bash
# Run in background
sudo nohup ./run_system.sh eth0 > agent.log 2>&1 &

# Check status
tail -f agent.log

# Stop
sudo pkill -f flow_capture
```

---

## 📊 Understanding the Output

### Live Console Output

Every 60 seconds (default), you'll see:

```
==============================================================
LIVE STATISTICS - 14:30:15
==============================================================

Flows Processed: 1247
Exports Received: 3

--- Count-Min Sketch ---
Total Bytes: 15,234,567
Total Packets: 34,521
Memory: 81,920 bytes

Top 5 Heavy Hitters (by bytes):
  192.168.1.10:54321->8.8.8.8:443/TCP: 5,234,890 bytes
  192.168.1.15:60123->1.1.1.1:443/TCP: 3,456,123 bytes
  ...

--- HyperLogLog ---
Unique Source IPs: 45
Unique Destination IPs: 123
Unique Flows: 892
Network Diversity: 18.74%

⚠ Potential Port Scanners Detected:
  10.0.0.66: 87 unique ports

Total Memory Usage: 245,760 bytes (240.0 KB)
Compression Ratio: 101.5x
==============================================================
```

### JSON Summary Files

Located in `output/aggregated_flows/summary_YYYY-MM-DD_HH-MM-SS.json`:

```json
{
  "timestamp": "2025-10-20T14:30:15",
  "flows_processed": 1247,
  "cms": {
    "heavy_hitters_bytes": [
      {
        "flow": "192.168.1.10:54321->8.8.8.8:443/TCP",
        "bytes": 5234890
      }
    ]
  },
  "hll": {
    "cardinalities": {
      "unique_src_ips": 45,
      "unique_dst_ips": 123
    },
    "port_scanners": [
      {"ip": "10.0.0.66", "unique_ports": 87}
    ]
  },
  "compression_ratio": 101.5
}
```

---

##