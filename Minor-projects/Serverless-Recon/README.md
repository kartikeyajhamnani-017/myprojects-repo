

# 🚀 Serverless Recon-Engine

## Overview

**Serverless Recon-Engine** is an event-driven, serverless threat intelligence pipeline built on Google Cloud Platform. It automatically enriches low-context security alerts (e.g., suspicious IP detections) with active reconnaissance data such as port scans and banner grabs.

The system is designed to eliminate manual investigation overhead, reduce infrastructure costs, and provide scalable, on-demand intelligence gathering.

---

## 🎯 Problem Statement

Security Operations Centers (SOCs) face **alert fatigue** due to high volumes of low-context alerts. While systems can detect suspicious IP activity, they lack immediate contextual intelligence such as:

* Is the IP running exposed services?
* Is it a botnet node or research scanner?
* What technologies are exposed?

Manual investigation does not scale, and maintaining always-on recon servers is cost-inefficient.

---

## ✅ Solution

This project implements a **serverless, event-driven enrichment pipeline** that:

* Triggers reconnaissance only when a threat is detected
* Performs concurrent port scanning and banner grabbing
* Enriches alerts automatically
* Stores high-fidelity intelligence records in BigQuery
* Scales to zero when idle (no idle server cost)

---

## 🏗 Architecture

### Core Flow

1. Honeypot logs suspicious IP → stored in **GCS**
2. GCS triggers **Pub/Sub notification**
3. Pub/Sub triggers a **Go-based Cloud Function**
4. Function:

   * Reads the log file
   * Performs concurrent port scans
   * Collects service banners
   * Inserts enriched results into **BigQuery**

---

## 🧱 Tech Stack

* **Language:** Go (concurrent network I/O)
* **Storage:** Google Cloud Storage (GCS)
* **Messaging:** Pub/Sub
* **Compute:** Cloud Functions (Gen 2)
* **Analytics:** BigQuery
* **Observability:** Structured Logging (slog) + Cloud Monitoring

---

## 🔐 Production Hardening

### 1. Dead-Letter Queue (DLQ)

Prevents infinite retry loops caused by malformed or corrupted messages.
After N failed delivery attempts, messages are routed to a quarantine topic.

### 2. Cost Safety Valve

`max-instances` is configured on Cloud Functions to:

* Cap concurrency
* Prevent runaway billing during attack spikes
* Apply backpressure via Pub/Sub

### 3. Idempotency Awareness

Handles Pub/Sub's at-least-once delivery model to prevent unintended duplicate processing.

---

## 📊 Observability

* Structured JSON logging (queryable in Cloud Logging)
* Correlation IDs from Pub/Sub message IDs
* Custom metrics:

  * Scan duration
  * Open ports detected
  * Error rates

---

## 🧠 Key Design Principles

* Event-driven architecture
* Decoupled processing
* Scale-to-zero infrastructure
* Resilience through DLQ
* Cost governance via concurrency limits
* Production-grade observability

---

## 💡 Why This Project Matters

This project demonstrates:

* Cloud-native system design
* Serverless architecture patterns
* Distributed systems thinking
* Security automation
* Production hardening strategies

It is not just a script — it is a fully architected, resilient, scalable intelligence pipeline.
