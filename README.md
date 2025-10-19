# Decentralized Flow Monitoring System for PC-Based Networks

* ``src/ebpf``: For eBPF kernel programs (C code).
* ``src/userspace``: For Python code that loads eBPF programs and processes data.
* ``tests``: For unit tests and virtual testbeds (e.g., Docker later).
* ``docs``: For notes, diagrams, or research papers.

## **Background:**

Traditional Network Security Monitoring tools are largely centralized: traffic is captured, aggregated, and analyzed in a central server, SIEM, or collector. While effective in enterprise datacenters, this model faces challenges when monitoring distributed PC-based environments, such as corporate offices, universities, or edge networks.

Research into decentralized IDS/NSM is still limited, and most existing solutions are either centralized (Zeek, Suricata, Elastic Stack) or focused on IoT/edge rather than general PC-based networks. This project fills that gap.

## **Description:**

The project proposes to design and implement a decentralized flow monitoring tool distributed across multiple PCs in a network. Each PC runs a lightweight agent that:

* Captures local network traffic at the flow level (5-tuple, byte/packet counts, timing).
* Compresses and aggregates traffic into summaries (using probabilistic data structures such as Count-Min Sketch or HyperLogLog).
* Shares these summaries with other agents or a distributed collector using a P2P overlay protocol (e.g., gossip/epidemic dissemination).
* Reconstructs a global view of network activity without requiring full centralization.

## **Objectives:**

The system must be designed to:

* Minimize performance overhead on end-user PCs.
* Scale with the number of nodes in the network.
* Remain resilient if some nodes fail or disconnect.

## **Tools & Technologies:**

* Traffic Capture: libpcap (C/Python wrapper) or eBPF (for low-overhead metadata capture).
* Compression/Aggregation: Probabilistic data structures (Count-Min Sketch, HyperLogLog, Bloom filters) in Python/Go/C implementations.
* Decentralized Communication: P2P frameworks: libp2p, gRPC, ZeroMQ, or gossip protocols.
* Data Processing & Visualization: Lightweight central viewer (Flask/Django web app, Grafana dashboard).
* Testing & Evaluation: Virtual testbeds (Docker, Mininet, or local VMs) or performance benchmarks (Linux perf, htop, sar).

## Authors
* Anna Melkumyan
* Cecília Maria Rodrigues Correia
* Eric Eugenio de Haro
* Oriol Ramos Puig
* Miquel Romeo 
* Sofian Aoulad
