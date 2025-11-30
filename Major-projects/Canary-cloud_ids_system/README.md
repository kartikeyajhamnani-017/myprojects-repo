# Canary: Cloud-Native Intrusion Detection System (IDS)
A high-throughput, rule-based intrusion detection engine built in Go. Designed for low-latency packet inspection in Kubernetes environments.

Canary is a lightweight IDS engineered to run as a Kubernetes Sidecar or DaemonSet. Unlike traditional, resource-heavy NIDS (Network Intrusion Detection Systems), Canary leverages Go's concurrency primitives to process network traffic in real-time with minimal CPU footprint. It decouples packet ingestion from analysis using buffered channels, ensuring resiliency against traffic bursts and preventing head-of-line blocking.

## 🏗️ Architecture
Canary operates on a Producer-Consumer model to maximize throughput. The system is divided into three decoupled layers: Ingestion, Buffering, and Analysis.

Figure 1: High-Level Event-Driven Pipeline showing the non-blocking data flow.

Core Design Decisions
Ingestion Layer (The Producer): The Packet Listener runs in Promiscuous Mode, capturing raw frames from the network interface via gopacket. It operates on a dedicated Goroutine to ensure that I/O operations never block the analysis logic.

Buffering Layer (The Shock Absorber): To handle micro-bursts of traffic (common in cloud environments), raw packets are pushed into a Buffered Channel (size: 1024 by default). This acts as a queue, providing backpressure handling. If the analysis workers are saturated, the buffer absorbs the spike, preventing immediate packet drops.

Analysis Layer (The Consumer Pool): A configurable pool of Concurrent Worker Goroutines reads from the buffer. This parallelization allows Canary to scale across multi-core CPUs, performing regex matching and signature analysis simultaneously on multiple packets.

Observability First: All alerts and logs are emitted as Structured JSON, making Canary natively compatible with log aggregators like Elasticsearch (ELK), Loki, or Fluentd without requiring complex parsing rules.

## 🚀 Key Features
⚡ Non-Blocking I/O: Utilizes Go channels to prevent the packet capture loop from stalling during heavy analysis loads.

🐳 Container-Ready: Designed with a small binary footprint (built on distroless or alpine) for efficient sidecar deployment.

🛡️ Rule-Based Engine: Supports hot-reloading of threat signatures defined in simple JSON/YAML configuration.

🔍 Port Scan Detection: Built-in heuristic engine to detect rapid connection attempts (Nmap/Netcat scans) in real-time.

## 🛠️ Quick Start
Prerequisites: libpcap-dev (Linux) or npcap (Windows).

Bash

### 1. Clone the repository
git clone https://github.com/yourusername/canary-ids.git

### 2. Build the binary
make build

### 3. Run in Audit Mode (Requires sudo for promiscuous mode)
sudo ./bin/canary --iface eth0 --workers 5
🔮 Roadmap
[ ] eBPF Integration: Migrating packet capture from user-space (pcap) to kernel-space (eBPF/XDP) for zero-copy performance.

[ ] Prometheus Exporter: Exposing metrics for packets_captured_total, packets_dropped, and alerts_triggered.

[ ] gRPC API: Enabling dynamic rule injection from a central control plane.



### Figure 1 :
```mermaid
flowchart TD
    %% Nodes
    User([User / Attacker])
    GCLB[Google Cloud Load Balancer]
    WAF[Cloud Armor WAF]
    
    subgraph "Production Environment"
        App[Portfolio Application]
    end

    subgraph "Canary Honeynet (The Trap)"
        Honeypot[Go Honeypot Cluster]
        style Honeypot fill:#f9f,stroke:#333,stroke-width:2px
    end

    subgraph "GCP Backend (The Brain)"
        PubSub[Cloud Pub/Sub]
        ML[Python ML Engine [Cloud Run]]
        Intent[Intent Analysis [Cloud Function]]
        Adapt[Adaptation Controller]
        BigQuery[BigQuery Logs]
        SCC[Security Command Center]
        Response[Response Cloud Function]
    end

    %% Edge Connections
    User --> GCLB
    GCLB -->|Clean Traffic| App
    GCLB -->|Suspicious Traffic| Honeypot
    
    %% The Trap Logic
    Honeypot -->|Raw Logs| PubSub
    PubSub --> Intent
    PubSub --> ML
    PubSub --> BigQuery
    
    %% The Feedback Loops
    Intent -->|Deception Command| Adapt
    Adapt -->|Morph Environment| Honeypot
    
    ML -->|High Confidence Alert| SCC
    SCC -->|Trigger Defense| Response
    Response -->|Update Blocklist| WAF
    WAF -.->|Block Future Attacks| GCLB

    %% Styling
    classDef cloud fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    class GCLB,WAF,PubSub,ML,Intent,Adapt,SCC,Response cloud;
