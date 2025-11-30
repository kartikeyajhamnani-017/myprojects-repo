```mermaid
flowchart TB
    %% External Access
    Client([Client App / Web])
    
    subgraph "Kubernetes Cluster"
        Ingress[Spring Cloud Gateway]
        
        subgraph "Services Layer"
            ProdService[Product Service]
            OrderService[Order Service]
            InvService[Inventory Service]
        end
        
        subgraph "Data Layer (Polyglot)"
            Mongo[(Product DB <br/> MongoDB)]
            Postgres[(Order DB <br/> PostgreSQL)]
            Redis[(Cache <br/> Redis)]
        end
        
        subgraph "Event Bus"
            RabbitMQ[RabbitMQ / Kafka]
        end
    end

    %% Connections
    Client -->|HTTPS| Ingress
    Ingress -->|/products| ProdService
    Ingress -->|/orders| OrderService
    
    %% Data Connections
    ProdService --> Mongo
    OrderService --> Postgres
    
    %% Async Communication
    OrderService -->|OrderPlacedEvent| RabbitMQ
    RabbitMQ -->|Consume Event| InvService
    InvService -->|Update Stock| Redis

    %% Styling
    classDef java fill:#ffcc80,stroke:#e65100,stroke-width:2px;
    class ProdService,OrderService,InvService,Ingress java;
    
    classDef db fill:#e0e0e0,stroke:#333,stroke-width:2px;
    class Mongo,Postgres,Redis db;
