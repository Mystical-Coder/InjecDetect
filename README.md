AI-Powered SQL Injection Security Gateway
This project implements a real-time, AI-powered security platform designed to detect and block SQL Injection (SQLi) attacks before they can reach upstream services. It leverages a microservices architecture, combining a resilient Java-based gateway with a high-performance Python deep learning service.

The core of the system is a custom-trained Bidirectional LSTM model that analyzes the contextual syntax of incoming requests, achieving 98% detection accuracy.

Architectural Overview
The system acts as an intelligent shield. All client traffic is first routed through the Spring Cloud Gateway, which inspects the request and queries the FastAPI service for a threat score. Based on this score, the gateway either blocks the request or allows it to proceed to the main application.

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

Key Features
Custom Deep Learning Model: A Bidirectional LSTM network built with TensorFlow/Keras, specifically trained to understand the syntax and patterns of SQLi attacks.

Rigorous Model Validation: The model's 98% accuracy was achieved and validated using Stratified 10-Fold Cross-Validation to ensure stable and generalizable performance.

Reactive Security Filter: A non-blocking GlobalFilter in Spring Cloud Gateway (WebFlux) inspects 100% of incoming traffic without impacting performance.

High Availability: Implemented with a Resilience4j Circuit Breaker that protects the gateway from downstream failures in the model service, using a fail-open strategy to maintain application uptime.

High-Performance Caching: An in-memory Caffeine cache stores the results of recent threat analyses, allowing the gateway to instantly block repetitive, high-throughput attacks in microseconds.

Decoupled Microservices: The separation of concerns between the Java gateway and the Python AI service allows for independent scaling, development, and resource management.

Technology Stack
Security Gateway (Java)
Framework: Spring Boot, Spring Cloud Gateway (WebFlux)

Resilience: Resilience4j (Circuit Breaker)

Caching: Caffeine

Build Tool: Gradle

Model Inference Service (Python)
Framework: FastAPI

Web Server: Uvicorn

Deep Learning: TensorFlow 2.10.0, Keras 2.10.0

Data Handling: Scikit-learn 1.2.2, NumPy 1.23.5, Pandas 1.5.3

Validation: Pydantic 1.10.12

Project Structure
.
├── Dataset/
│   └── sqli-extended.csv
├── model_service/
│   ├── app.py                  # FastAPI inference service
│   ├── dummy_service.py        # Mock upstream application for testing
│   ├── requirements.txt
│   ├── sql_injection_detection.h5 # The trained Keras model
│   └── tokenizer.pkl           # The tokenizer for preprocessing
└── SQLi-Security-Gateway/
    ├── build.gradle
    └── src/
        └── main/
            ├── java/           # Spring Cloud Gateway source code
            └── resources/
                └── application.yml

How to Run This Project (Locally)
Follow these steps to run the complete application on your local machine.

Prerequisites
Java 17 or higher

Gradle 7.5 or higher

Python 3.9+

pip for Python package management

Step 1: Start the Model Inference Service
Open a new terminal and navigate to the model_service directory.

Install Python dependencies:

pip install -r requirements.txt

Run the FastAPI server:

uvicorn app:app --host 0.0.0.0 --port 8000

You should see a message indicating Uvicorn is running on port 8000.

Step 2: Start the Mock Upstream Service
This is a simple service that the gateway will forward legitimate requests to.

Open a new, separate terminal and navigate to the model_service directory.

Run the dummy service:

python dummy_service.py

This service will now be running on port 8081.

Step 3: Start the Security Gateway
Open a third terminal and navigate to the SQLi-Security-Gateway directory.

Run the Spring Boot application using Gradle:

./gradlew bootRun

The gateway will start up on port 8080.

Step 4: Test the System
Your entire platform is now running! You can test it by sending requests to the gateway's port (8080).

Send a Benign Request (Should be ALLOWED)

curl -X POST http://localhost:8080/api/v1/user -H "Content-Type: application/json" -d '{"username": "testuser", "comment": "This is a normal comment."}'

You will receive a 200 OK response.

Send a Malicious Request (Should be BLOCKED)

curl -X POST http://localhost:8080/api/v1/user -H "Content-Type: application/json" -d '{"username": "admin", "comment": "search '' OR 1=1 --"}'

You will receive a 403 Forbidden response.