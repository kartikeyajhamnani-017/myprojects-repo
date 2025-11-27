```mermaide

graph TD
    %% Styling
    classDef input fill:#f9f,stroke:#333,stroke-width:2px;
    classDef core fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
    classDef storage fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;
    classDef output fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;

    subgraph External_Traffic [Network Layer]
        Traff[Incoming Traffic / Packets]:::input
    end

    subgraph Canary_Core [Canary Engine (Go Runtime)]
        direction TB
        Listener[Packet Listener / PCAP]:::core
        Buffer(Buffered Channel / Queue):::core
        Workers[Concurrent Analysis Workers]:::core
        Engine{Rule Matching Engine}:::core
        
        Listener -->|Raw Bytes| Buffer
        Buffer -->|De-queue| Workers
        Workers -->|Payload Inspection| Engine
    end

    subgraph Configuration [Config Layer]
        Rules[(Threat Signatures JSON)]:::storage
        Config[(System Config YAML)]:::storage
    end

    subgraph Outputs [Observability & Alerts]
        Stdout[Structured Logs (JSON)]:::output
        Webhook[Webhook / Slack Alert]:::output
    end

    %% Relationships
    Traff -->|Promiscuous Mode| Listener
    Rules -.->|Load on Start| Engine
    Config -.->|Init| Listener
    Engine -->|Match Found| Stdout
    Engine -->|Critical Severity| Webhook
    
    %% Context Note
    note[High-Throughput / Non-Blocking] -.-> Buffer
