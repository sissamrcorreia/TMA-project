# Traffic Monitor Agent (TMA)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-24.0%2B-blue?style=for-the-badge&logo=docker)
![eBPF](https://img.shields.io/badge/eBPF-Powered-orange?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

This project implements a high-performance, eBPF-based network traffic monitoring system for next-generation data centers. The system moves monitoring workloads from network switches to end hosts (servers) to overcome the limitations of traditional switch-based monitoring.

---

## 💡 The Challenge
Legacy monitoring tools (like `tcpdump` or `Wireshark`) rely on **user-space packet capture**, which requires copying every packet from the kernel. 
*   **The Problem:** At high speeds (10Gbps+), this copying saturates the CPU, causing **packet loss (>50%)** and **observer effect** (slowing down the app).
*   **The Solution:** TMA uses **eBPF (Extended Berkeley Packet Filter)** to analyze traffic **inside the kernel** (Zero-Copy). It aggregates stats into compact "Sketches" (CMS/HLL) and sends only lightweight telemetry metadata to user space.

---

## 📁 Project Structure

- **`v1/`** - Initial version
- **`v2/`** - **Final version** ← **Current/Active Version**

---

## 🚀 About Version 2

Version 2 is our complete implementation featuring:

- **eBPF-powered kernel-space monitoring** for zero-copy packet analysis
- **Real-time traffic analytics** with Count-Min Sketch and HyperLogLog
- **Distributed edge monitoring** across containerized hosts
- **Interactive dashboard** for visualization and threat detection
- **High-fidelity 5-tuple flow tracking** (`Source IP`, `Dest IP`, `Source Port`, `Dest Port`, `Protocol`)

---

## 🔧 Quick Start

1. Navigate to the `v2/` directory:
   ```bash
   cd v2
   ```

2. Start the system:
   ```bash
   docker-compose up --build -d
   ```

3. Access the dashboard at [http://localhost:8501](http://localhost:8501)

---

## 📚 Documentation

Detailed documentation for each version:

- [v1 README](./v1/README.md) - Initial implementation details and usage
- [v2 README](./v2/README.md) - **Final implementation details and usage**

---

## 👥 Authors

**Group A1**  
Anna Melkumyan Canosa | Cecília Maria Rodrigues Correia | Eric Eugenio de Haro | Miquel Romero | Oriol Ramos Puig
