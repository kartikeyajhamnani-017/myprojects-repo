# LedgerEz – Secure Digital Ledger (Spring Boot + React)

A full-stack fintech-style ledger application built with Spring Boot (JWT Security) and React, implementing stateless authentication and production-structured backend architecture.

This project demonstrates secure REST API design, Spring Security internals, and frontend-backend integration.

---

## 🔐 Key Highlights

- Stateless JWT Authentication  
- Spring Security (Custom AuthenticationProvider)  
- BCrypt password hashing  
- CORS-secured API (Frontend on port 3000)  
- Role-ready architecture (extensible)  
- Clean layered backend structure  
- Modern React UI with protected routes  

---

## 🏗 Tech Stack

### Backend

- Java 17  
- Spring Boot 3  
- Spring Security  
- JWT  
- JPA / Hibernate  
- PostgreSQL  

### Frontend

- React  
- React Router  
- Context API  
- Axios  

---

## 🧠 Architecture
```bash
React (3000)
↓
Spring Boot API (9000)
↓
PostgreSQL
```


### Authentication Flow


* Login → AuthenticationManager → JWT → Client stores token → Protected API access

---

## 🚀 Features

- User Registration & Login  
- Wallet Management  
- Contact Management  
- Transaction Tracking  
- Dashboard Foundation  
- Protected API Endpoints  
- Stateless Session Policy  

## 🎯 What I learned 

- Deep understanding of Spring Security configuration  
- Manual AuthenticationManager usage  
- Custom DaoAuthenticationProvider wiring  
- JWT filter implementation  
- Secure frontend-backend integration  
- Production-ready project structure  

---