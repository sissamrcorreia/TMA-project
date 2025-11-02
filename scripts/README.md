
# 🧩 TMA Project — Local Deployment & Usage Guide

This document provides **step-by-step instructions** to set up, run, and understand the TMA (Transit Monitoring & Analysis) project using Docker.  
It also explains the internal parameters that control the fake traffic generation for each peer.

---

## 🐳 1. Installing Docker and Docker Compose

Run the following commands to install Docker Engine, CLI, and Compose plugin:

```bash
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
sudo usermod -aG docker $USER

```
---

## 🧱 2. Project Structure Overview

ddddd
```bash
TMA-project/
├── python-version/             # Monitoring system (capture + aggregation)
│   └── src/
│       ├── capture/
│       ├── aggregation/
│       ├── output/
│       ├── run_system.sh
│       └── requirements.txt
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/
│   ├── start_peers.sh
│   ├── stop_peers.sh
│   ├── clean_data.sh
│   ├── traffic_generator.py
│   ├── peer_entry.sh
│   └── README.md   ← (this file)
└── data/
    ├── peer1/
    ├── peer2/
    ├── peer3/
    ├── peer4/
    └── peer5/
    
```
---
🧰 4. Building/Start/Stop the Project
---
On `TMA-project/scripts`
```bash
chmod +x scripts/*.sh
sudo ./start_peers.sh
sudo ./stop_peers.sh
