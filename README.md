# AI-Powered SQL Injection Security Gateway

**This project implements a real-time, AI-powered security platform designed to detect and block SQL Injection (SQLi) attacks before they reach upstream services.** It combines a resilient Java-based gateway with a high-performance Python deep learning service.

---

## **Overview**

**Core idea:** All client traffic passes through a Spring Cloud Gateway which inspects requests and queries a FastAPI model service for a threat score. Based on the score, the gateway either **blocks** the request or **allows** it to proceed.

```
[Client Request] -> [Spring Cloud Gateway (Port 8080)]
                         |
                         | 1. Intercepts & Extracts Payload
                         | 2. Checks Cache
                         | 3. Calls Model Service (if not cached)
                         |
                         +------> [FastAPI Model Service (Port 8000)]
                         |           |
                         |           | Returns Threat Score (e.g., 0.99)
                         |           V
                         | 4. Receives Score & Makes Decision
                         |
    (BLOCKS - 403 Forbidden) <-----+ (If score > threshold)
                         |
                         | (ALLOWS)
                         V
              [Upstream Application (Port 8081)]
```

---

## **Key Features**

* **Custom Deep Learning Model:** Bidirectional LSTM (TensorFlow / Keras) trained specifically to detect SQLi patterns.
* **Rigorous Validation:** Stratified 10-Fold Cross-Validation used to validate model performance (**98% accuracy** reported).
* **Reactive Security Filter:** Non-blocking `GlobalFilter` in Spring Cloud Gateway (WebFlux) inspects 100% of traffic without impacting throughput.
* **Resilience:** `Resilience4j` circuit breaker protects the gateway from downstream failures (fail-open strategy to preserve uptime).
* **High-Performance Caching:** In-memory **Caffeine** cache for extremely fast repeat lookups.
* **Decoupled Microservices:** Java gateway and Python AI service scale independently and enable faster iteration.

---

## **Technology Stack**

**Security Gateway (Java)**

* Framework: **Spring Boot**, **Spring Cloud Gateway (WebFlux)**
* Resilience: **Resilience4j (Circuit Breaker)**
* Caching: **Caffeine**
* Build Tool: **Gradle**

**Model Inference Service (Python)**

* Framework: **FastAPI**
* Web Server: **Uvicorn**
* Deep Learning: **TensorFlow 2.10.0**, **Keras 2.10.0**
* Data Handling: **scikit-learn 1.2.2**, **NumPy 1.23.5**, **Pandas 1.5.3**
* Validation / Schemas: **Pydantic 1.10.12**

---

## **Project Structure**

```
.
├── Dataset/
│   └── sqli-extended.csv
├── model_service/
│   ├── app.py                  # FastAPI inference service
│   ├── dummy_service.py        # Mock upstream application for testing
│   ├── requirements.txt
│   ├── sql_injection_detection.h5 # Trained Keras model
│   └── tokenizer.pkl           # Tokenizer for preprocessing
└── SQLi-Security-Gateway/
    ├── build.gradle
    └── src/
        └── main/
            ├── java/           # Spring Cloud Gateway source code
            └── resources/
                └── application.yml
```

---

## **How to Run This Project (Locally)**

### **Prerequisites**

* **Java 17** or higher
* **Gradle 7.5** or higher
* **Python 3.9+**
* **pip** (Python package manager)

### **Step 1: Start the Model Inference Service**

1. Open a terminal and `cd` into `model_service/`.
2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Run the FastAPI server:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

You should see Uvicorn running on port **8000**.

### **Step 2: Start the Mock Upstream Service**

1. Open a new terminal and `cd` into `model_service/`.
2. Run the dummy service:

```bash
python dummy_service.py
```

This will start the upstream mock on port **8081**.

### **Step 3: Start the Security Gateway**

1. Open a third terminal and `cd` into `SQLi-Security-Gateway/`.
2. Run the Spring Boot application using Gradle:

```bash
./gradlew bootRun
```

The gateway will listen on port **8080**.

### **Step 4: Test the System**

**Send a benign request (should be ALLOWED):**

```bash
curl -X POST http://localhost:8080/api/v1/user \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "comment": "This is a normal comment."}'
```

Response: **200 OK**

**Send a malicious request (should be BLOCKED):**

```bash
curl -X POST http://localhost:8080/api/v1/user \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "comment": "search '' OR 1=1 --"}'
```

Response: **403 Forbidden**

---
