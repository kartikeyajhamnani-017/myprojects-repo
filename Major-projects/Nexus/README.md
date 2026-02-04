# Nexus: Scalable Cloud-Native E-Commerce Backend

**Nexus** is a modern, enterprise-grade backend platform built to overcome the scalability and reliability limitations of traditional monolithic e-commerce systems.

Instead of tightly coupled components competing for the same resources, Nexus decomposes the platform into independently deployable microservices powered by **event-driven communication** and **polyglot persistence**—allowing the system to scale as business demand evolves.

> **Note:** Nexus is designed as an educational yet production-inspired blueprint for building cloud-native, fault-tolerant, and horizontally scalable backend systems, aligned with architectural patterns used by high-scale platforms like Amazon and Netflix.

---

## 🏗 System Architecture (The Vision)

Nexus follows a **Decouple → Distribute → Scale** model. Each service owns its domain, manages its own data, and communicates via events—resulting in a system that remains responsive even under load or partial failures.

### 1️⃣ Distributed Microservices Core
Independently deployable backend services written in **Java 17 + Spring Boot**, each responsible for a specific business domain:
* **Order Service:** Transactional, ACID-heavy operations.
* **Product Catalog Service:** Read-optimized with flexible schemas.
* **User Service:** Authentication & profile management.
* **Inventory Service:** Real-time stock synchronization & consistency.

### 2️⃣ Polyglot Persistence
Nexus uses the "right database for the job" rather than a one-size-fits-all solution:
* **PostgreSQL:** ACID-compliant storage for Order operations and User records.
* **MongoDB:** Flexible, schema-less storage for the Product Catalog.
* **Redis:** High-speed caching for real-time stock lookups.

### 3️⃣ Event-Driven Communication
Instead of blocking synchronous API calls, Nexus uses **RabbitMQ** (swappable for Kafka) for asynchronous communication:
* When an order is placed, an `OrderPlacedEvent` is published.
* The Inventory Service consumes this and updates stock independently.
* *Result:* Products remain available even if downstream services are temporarily offline (Eventual Consistency).

### 4️⃣ API Gateway (Single Entry Point)
A **Spring Cloud Gateway** manages routing, security filtering, rate limiting, and entry-point observability, ensuring frontends interact with the system through a unified and secure interface.

### 5️⃣ Observability & Infrastructure
For real-world operational readiness, Nexus is designed to integrate:
* **Service Discovery:** Eureka/Consul
* **Centralized Logging:** ELK Stack
* **Monitoring:** Prometheus + Grafana




## 🚀 Current Release(MVP): 

Current Development Phase: Polyglot Foundation & Event Loop

The current MVP focuses on establishing the core architectural backbone that future features will build upon. This phase lays the groundwork for proper scaling, reliability, and service decoupling.

## ✅ Key Capabilities in v0.1.0

### 1. Polyglot Data Layer

The following services are fully functional and running simultaneously:

Order-Service with PostgreSQL

Product-Service with MongoDB

Both services implement domain-specific models and manage their own persistent storage.

### 2. Spring Cloud Gateway Integration

A fully functioning gateway that:

Listens on port 8080

Forwards traffic to the correct internal service

Provides a clean separation between frontend clients and backend microservices

### 3. Asynchronous Event Pipeline

RabbitMQ acts as the event broker:

OrderService publishes OrderPlacedEvent

InventoryService consumes the message asynchronously

Stock levels are updated in real time

This showcases the backbone of event-driven design and eventual consistency.

### 4. Containerized Deployment

A complete docker-compose environment orchestrates:

API Gateway

Every microservice

MongoDB

PostgreSQL

Redis

RabbitMQ

This enables one-command local deployment that mirrors a production-ready distributed system.

## 🔮 Roadmap (Future Vision)

Full Inventory-Service persistence

User-Service authentication (JWT + OAuth2)

Improved read-model caching (Redis-backed query layer)

Kubernetes manifests (GKE / Minikube setups)

Long-Term Vision

CQRS + Event Sourcing

Distributed tracing (OpenTelemetry)

Multi-region deployments

Horizontal pod autoscaling (HPA)

Resilient patterns (circuit breakers, retries, backpressure)

## 🧭 Why Nexus Matters : 

Nexus demonstrates deep understanding of:

* Microservices architecture
* Event-driven system design
* Polyglot persistence
* Domain-driven service boundaries
* Distributed systems operational concerns


---

## 📊 System Diagram


```mermaid
flowchart TB

%% ================================
%% Client & Gateway
%% ================================
Client([Client App / Web])
Client -->|HTTPS| APIGW

subgraph Layer1["API Gateway Layer"]
    APIGW[Spring Cloud Gateway]
end

%% ================================
%% MICROSERVICES (Hierarchical Layout)
%% ================================
subgraph Layer2["Distributed Microservices"]
    direction TB
    
    %% Rank 1: The Process Starter
    OrderService[Order Service<br/>Spring Boot]
    
    %% Rank 2: The Reactor
    InventoryService[Inventory Service<br/>Spring Boot]
    
    %% Rank 3: The Data Providers
    UserService[User Service<br/>Spring Boot]
    ProductService[Product Service<br/>Spring Boot]

    %% Invisible links to force vertical layout (Order -> Inventory -> Product/User)
    OrderService ~~~ InventoryService
    InventoryService ~~~ ProductService
    InventoryService ~~~ UserService
end

%% Gateway Routing
APIGW --> OrderService
APIGW --> UserService
APIGW --> ProductService
APIGW --> InventoryService

%% ================================
%% EVENT BUS (Async Communication)
%% ================================
subgraph Layer3["Event Bus (Async)"]
    Broker[RabbitMQ / Kafka]
end

%% The Event Flow (Clean Downward/Side Lines)
OrderService -->|OrderPlacedEvent| Broker
Broker -->|Consume Event| InventoryService

%% ================================
%% DATA LAYER (Polyglot)
%% ================================
subgraph Layer5["Data Layer (Polyglot Persistence)"]
    OrderDB[(Order DB<br/>PostgreSQL)]
    Cache[(Stock Cache<br/>Redis)]
    UserDB[(User DB<br/>PostgreSQL)]
    ProductDB[(Product DB<br/>MongoDB)]
end

%% Data Connections (Directly below respective services)
OrderService --> OrderDB
InventoryService --> Cache
UserService --> UserDB
ProductService --> ProductDB

%% Cross-Service Data Update (Inventory updates Product DB)
InventoryService -->|Update Stock| ProductDB

%% ================================
%% CROSS-CUTTING CONCERNS (Discovery & Obs)
%% ================================
%% Grouping these to the side or bottom to avoid clutter
subgraph Shared["Infrastructure Support"]
    Discovery[(Service Discovery<br/>Eureka/Consul)]
    Logs[Centralized Logging<br/>ELK Stack]
    Metrics[Monitoring<br/>Prometheus/Grafana]
end

%% Connected vaguely to Layer 2 to imply "All Services"
Layer2 -.-> Discovery
Layer2 -.-> Logs
Layer2 -.-> Metrics

%% ================================
%% STYLING (Vibrant Version)
%% ================================

%% Gateway (Cool Blue)
classDef gateway fill:#c8e6ff,stroke:#01579b,stroke-width:2px,color:#003c71,font-weight:bold;
class APIGW gateway;

%% Microservices (Warm Orange)
classDef service fill:#ffddbc,stroke:#e65100,stroke-width:2px,color:#5a2b00,font-weight:bold;
class OrderService,UserService,InventoryService,ProductService service;

%% Databases (Neutral Light Gray + Dark Border)
classDef db fill:#f7f7f7,stroke:#424242,stroke-width:2px,color:#1b1b1b,font-weight:bold;
class UserDB,ProductDB,OrderDB,Cache db;

%% Event Bus (Vibrant Pink)
classDef event fill:#ffd6e5,stroke:#ad1457,stroke-width:2px,color:#5a0930,font-weight:bold;
class Broker event;

%% Infrastructure (Purple Accent)
classDef infra fill:#e5c7ff,stroke:#6a1b9a,stroke-width:2px,stroke-dasharray: 5 5,color:#3b0a57,font-weight:bold;
class Discovery,Logs,Metrics infra;






