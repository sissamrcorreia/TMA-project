# Distributed Data Center Traffic Monitor
Project of Network Traffic Monitoring and Analysis

## 1. The Problem
**The Monitoring Bottleneck:** Modern data centers run on high-speed links (10G/40G/100G) that overwhelm standard network switches.

**Resource Scarcity:** Switches lack the CPU and memory (SRAM) to inspect every packet at line rate.

**Inaccuracy:** Current solutions rely on "Sampling" (e.g., NetFlow picks 1 out of every 1000 packets), which destroys accuracy. It misses micro-bursts and cannot reliably detect security threats like worms or scanners.

**Rigidity:** Hardware-based monitoring is hard to update or evolve.

## 2. Our Solution
**Distributed "Edge" Monitoring:** Instead of burdening the switch, we move the monitoring workload to the **End Hosts (Servers)**, which have abundant CPU/RAM resources.

**Architecture:** We simulate a Data Center using Docker Containers.

**The Agent:** A lightweight C program runs on every container. It captures traffic, summarizes it locally, and sends lightweight reports to a central collector.

**The "Duplicate" Fix:** To prevent double-counting traffic (once at source, once at destination), Agents will strictly capture only Outgoing (Egress) traffic.

**Use Cases:** Beyond Heavy Hitters (HHH), we will detect DDoS attacks and Superspreaders (scanners).

## 3. Authors
**Group A1**

Anna Melkumyan Canosa; Cecília Maria Rodrigues Correia; Eric Eugenio de Haro; Miquel Romero; Oriol Ramos Puig
