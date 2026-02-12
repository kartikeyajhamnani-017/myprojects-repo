# System Overview

Sentinel is designed as a Funnel Architecture, prioritizing high-speed data ingestion while offloading complex security analysis to a dedicated background process. This decoupling ensures that legitimate user traffic is never slowed down by heavy machine learning computations.

The system is composed of three distinct microservices, each optimized for a specific role in the data pipeline:

## 1. The Shield (Ingestion Layer)

**Technology:** Golang (net/http)

**Role:** The "Speed Gate."

**Why it exists:** Security checks shouldn't create latency. Go was chosen for its raw performance and concurrency handling (Goroutines). "The Shield" accepts thousands of concurrent HTTP requests, performs an ultra-fast Rule-Based check (microseconds), and immediately pushes the data to the queue. If a request is obviously malicious (e.g., contains `<script>`), it is blocked here instantly.

## 2. The Buffer (Queuing Layer)

**Technology:** Redis (Lists & Pub/Sub)

**Role:** The "Shock Absorber."

**Why it exists:** Traffic spikes happen. If 10,000 requests hit the system in one second, a synchronous ML engine would crash. Redis acts as a high-throughput buffer that creates a Producer-Consumer relationship. It persists data to disk (AOF enabled), ensuring that even if the analysis engine crashes, no logs are ever lost ("Nuclear Resurrection" safe).

## 3. The Brain (Analysis Layer)

**Technology:** Python (Scikit-Learn, Isolation Forest)

**Role:** The "Deep Scanner."

**Why it exists:** Go is fast, but Python is smart. "The Brain" consumes data from the Redis queue and uses Unsupervised Machine Learning (Isolation Forest) to detect anomalies. Unlike standard WAFs that look for known signatures, this component looks for statistical deviations—catching zero-day attacks, obfuscated payloads, and "weird" behavior that bypasses static rules.

## 4. The Admin (Dashboard Layer)
**Technology:**  Java (Spring Boot, WebSockets)

**Role:** The "Control."

**Why it exists:** Security teams need visibility. "The Admin" subscribes to the Redis Pub/Sub channel to receive real-time alerts. It uses WebSockets to push live attack data to the frontend (React/HTML) instantly, without requiring page refreshes. It also manages the persistent database (PostgreSQL) for historical reporting and audit trails.
