# 🛡️ **Canary: Cloud-Native Intrusion Detection & Active Defense System**

Canary is a next-generation **active defense and deception platform** designed to operate like a **cloud-native immune system**.
Instead of relying on static firewall rules or signature-based IDS modules, Canary **diverts**, **analyzes**, **learns**, and **adapts** to adversarial behavior—continuously strengthening infrastructure defenses in real time.

This project explores the future of intelligent cloud security through a **Divert → Detect → Defend → Adapt** pipeline.

---

## 🏗️ **Architectural Vision (Long-Term Roadmap)**

The long-term goal of Canary is to evolve into a fully autonomous, cloud-native defense system that:

* Transparently diverts suspicious traffic to a honeynet
* Performs advanced ML-based behavioral and intent analysis
* Adapts the deception environment based on attacker behavior
* Automatically updates edge defenses across the cloud

Below is the future-state architecture implemented in Google Cloud (GCP), as shown in the System Architecture diagram.

---

### 🔀 **Divert — Intelligent Traffic Steering**

* **Google Cloud Load Balancer (GCLB)** routes legitimate users to production.
* Suspicious or anomalous traffic is silently redirected to the **Canary Honeynet**, isolating and containing adversaries.

---

### 🧠 **Detect — Multi-Layer Behavioral Analytics**

Captured honeypot events are published to **Cloud Pub/Sub**, where multiple analysis pipelines operate:

#### **ML Engine (Cloud Run)**

* Performs attacker classification and behavior modeling.
* Generates high-confidence malicious intent predictions.

#### **Intent Analysis (Cloud Function)**

* Extracts the attacker’s objectives (reconnaissance, password spraying, exploitation attempts).
* Maps intent to an appropriate deception response.

#### **BigQuery Logs**

* Acts as the long-term data lake for threat hunting, dashboards, and retrospective analysis.

---

### 🔁 **Adapt — Dynamic Deception Surface**

* The **Adaptation Controller** adjusts honeypot responses and fingerprints (banners, protocols, delays, errors).
* Produces an environment that continuously evolves, slowing down attackers and increasing visibility.

---

###  🛡 **Defend — Automated Remediation Pipeline**

A high-confidence malicious event flows through:

`ML Engine → Security Command Center → Response Cloud Function → Cloud Armor WAF`

This pipeline automatically updates WAF rules to block future attacks **at the edge**, across all services, with no manual intervention.

---

## 🚀 **Current Release:  (MVP)**

The current version focuses on the **core detection and containment substrate** that will scale into the full cloud-native architecture.

This MVP is intentionally lightweight—but architecturally aligned—so contributors can extend real components toward the vision.

---

### ⚙️ **1. High-Performance Honeypot (Go)**

* Concurrent, event-driven trap service emulating SSH & HTTP endpoints.
* Captures brute-force attempts, scanning behavior, and early-stage recon.
* Designed to scale horizontally as the Canary Honeynet evolves.

---

### 🧩 **2. Analysis Engine (Python)**

* Normalizes raw honeypot telemetry into structured JSON events.
* Includes a rule-based detection layer capable of:

  * port scanning detection
  * brute-force / dictionary attempts
  * reconnaissance patterns

This forms the foundation for the ML and intent-analysis pipelines.

---

### 🐳 **3. Containerized Architecture**

* Fully Dockerized with isolated microservices (`Trap` and `Brain`).
* Communicate via a secure internal virtual network.
* Enables reproducible development, CI/CD integration, and cloud deployment.

---

### 🚫 **4. Mock Defense Layer**

* Simulates a Cloud Armor–style blocklist using `blocklist.json`.
* Automatically blocks flagged IPs inside the container network.
* Serves as a functional prototype for the future remediation pipeline.

---

## 🔄 **How the MVP Connects to the Vision**

| MVP Component       | Future Vision Component              |
| ------------------- | ------------------------------------ |
| Go honeypot         | Canary Honeynet Cluster              |
| Python rules engine | ML Engine + Intent Analysis          |
| Docker services     | Cloud Run + Cloud Functions          |
| Local blocklist     | Cloud Armor WAF automation           |
| JSON logs           | Pub/Sub → BigQuery pipeline          |
| Basic detection     | Adaptive deception + SCC integration |

The MVP is **not a separate prototype**—it is the **base layer of the final architecture**, intentionally engineered so every component can be replaced or scaled into a cloud-native equivalent.

---

## 🤝 **Why This Project Matters**

* Modern cloud attacks are orchestrated, automated, and behavior-driven.
* Defense systems must evolve beyond static signatures and slow manual responses.
* Canary demonstrates how cloud-native primitives + ML + deception can build a **self-learning, self-healing defense system**.

It is a unique intersection of:

* Cloud security
* Machine learning
* Distributed systems
* Deception technology
* Automation & response engineering



---


###  The System Architecture diagram 
```mermaid 
flowchart TD

    %% =========================
    %% Nodes
    %% =========================
    User([User / Attacker])
    GCLB[Google Cloud Load Balancer]
    WAF[Cloud Armor WAF]

    subgraph Production[Production Environment]
        App[Portfolio Application]
    end

    subgraph Honeynet[Canary Honeynet - The Trap]
        Honeypot[Go Honeypot Cluster]
    end

    subgraph Backend[GCP Backend - The Brain]
        PubSub[Cloud Pub/Sub]
        ML[Python ML Engine - Cloud Run]
        Intent[Intent Analysis - Cloud Function]
        Adapt[Adaptation Controller]
        BigQuery[BigQuery Logs]
        SCC[Security Command Center]
        Response[Response Cloud Function]
    end


    %% =========================
    %% Edges
    %% =========================
    User --> GCLB
    GCLB -->|Clean Traffic| App
    GCLB -->|Suspicious Traffic| Honeypot

    Honeypot -->|Raw Logs| PubSub
    PubSub --> Intent
    PubSub --> ML
    PubSub --> BigQuery

    Intent -->|Deception Command| Adapt
    Adapt -->|Morph Environment| Honeypot

    ML -->|High Confidence Alert| SCC
    SCC -->|Trigger Defense| Response
    Response -->|Update Blocklist| WAF
    WAF -.->|Block Future Attacks| GCLB


    %% =========================
    %% Styling (Vibrant Theme)
    %% =========================
    classDef cloud fill:#c7ebff,stroke:#0077b6,stroke-width:2px,color:#003049;
    classDef trap fill:#ffb3e6,stroke:#b30086,stroke-width:2px,color:#4a0035;
    classDef prod fill:#d2f8d2,stroke:#1b5e20,stroke-width:2px,color:#003300;
    classDef backend fill:#e6ccff,stroke:#5a189a,stroke-width:2px,color:#240046;

    class GCLB,WAF,PubSub,ML,Intent,Adapt,SCC,Response cloud;
    class Honeypot trap;
    class App prod;
    class BigQuery backend;
