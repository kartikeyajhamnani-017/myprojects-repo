```mermaid
graph TD
    %% Styling - Professional Microservices Palette
    classDef client fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000;
    classDef service fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000;
    classDef bus fill:#fff9c4,stroke:#fbc02d,stroke-width:2px,stroke-dasharray: 5 5,color:#000;
    classDef db fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000;

    subgraph Clients ["Client Layer"]
        Web["Web Frontend (React)"]:::client
        Mobile["Mobile App"]:::client
    end

    subgraph API_Gateway ["API Gateway"]
        Gateway["Nginx / Ingress Controller"]:::service
    end

    subgraph Service_Mesh ["Microservices Mesh (gRPC & HTTP)"]
        direction TB
        Auth["Auth Service (JWT)"]:::service
        Order["Order Service"]:::service
        Inventory["Inventory Service"]:::service
        Payment["Payment Service"]:::service
    end

    subgraph Event_Bus ["Async Event Bus"]
        Kafka[("Apache Kafka / RabbitMQ")]:::bus
    end

    subgraph Data_Layer ["Persistence (Database per Service)"]
        AuthDB[("Redis (Sessions)")]:::db
        OrderDB[("Postgres (Orders)")]:::db
        InvDB[("MongoDB (Products)")]:::db
    end

    %% Sync Calls
    Web -->|HTTPS| Gateway
    Gateway -->|gRPC| Auth
    Gateway -->|gRPC| Order
    
    %% Async Events
    Order -- "Topic: OrderCreated" --> Kafka
    Kafka -- "Consume" --> Inventory
    Kafka -- "Consume" --> Payment

    %% Data Connections
    Auth --> AuthDB
    Order --> OrderDB
    Inventory --> InvDB

    %% Context Note
    note["Event-Driven / Saga Pattern"] -.-> Kafka
