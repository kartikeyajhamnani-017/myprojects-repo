# 📌 Internal Flag Manager

## 🧩 Overview

**Internal Flag Manager** is a Spring Boot-based RESTful CRUD application designed to manage internal feature flags within a system.

It enables controlled activation/deactivation of application features, making it useful for:

- Feature rollouts  
- Controlled experiments  
- Operational toggles  
- Internal configuration management  

The application uses PostgreSQL for persistent storage and follows clean layered architecture principles.

---

## ⚙️ Tech Stack

- **Java 17+**
- **Spring Boot**
- **Spring Data JPA (Hibernate)**
- **PostgreSQL**
- **Maven**
- REST APIs

---

## 🏗 Architecture

The project follows a standard layered architecture:

Controller → Service → Repository → Database

- **Controller Layer** – Exposes REST endpoints  
- **Service Layer** – Contains business logic  
- **Repository Layer** – Handles DB interactions via JPA  
- **PostgreSQL** – Persistent data storage  

---

## 🗄 Database Configuration

The application uses environment variables for database credentials.

### Required Environment Variables

```bash
DB_URL=jdbc:postgresql://localhost:5432/FeatureDB
DB_USER=postgres
DB_PASSWORD=your_password