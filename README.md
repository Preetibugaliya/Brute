# 🛡️ BruteShield — Brute Force Attack Detection Tool

### 🔐 AI-Powered Cybersecurity Dashboard for Real-Time Threat Detection

---

## 📌 Overview

**BruteShield** is a full-stack cybersecurity system designed to detect and analyze brute force attacks in real time. It combines rule-based detection with machine learning to identify suspicious login patterns such as brute force, credential stuffing, and distributed attacks.

The system features a modern dashboard, real-time monitoring, and automated risk scoring to simulate a professional Security Operations Center (SOC) environment.

---

## 👨‍💻 Developed By

**Preeti Bugaliya**

---

## 🚀 Key Features

* 🔍 Real-time brute force detection
* 🤖 AI-based anomaly scoring (Isolation Forest)
* 📊 Live cybersecurity dashboard
* ⚡ WebSocket-based real-time logs
* 🚨 Alert system with notifications
* 🔐 Secure authentication using JWT
* 📁 Export logs (CSV)
* 🛑 IP blocking simulation

---

## 🏗️ System Architecture

### 🔙 Backend

* Built using **FastAPI**
* Handles authentication, APIs, detection logic, and WebSockets

### 🎯 Detection Engine

* Detects:

  * Brute Force Attacks
  * Distributed Attacks
  * Credential Stuffing
* Uses **Machine Learning (Isolation Forest)** for anomaly scoring

### 🎨 Frontend

* Interactive dashboard using HTML, CSS, JavaScript
* Displays logs, charts, alerts, and system metrics

---

## ⚙️ Tech Stack

**FastAPI, Python, scikit-learn, WebSockets, JavaScript, HTML, CSS, JWT Authentication, Uvicorn**

---

## 📡 API Endpoints

* `POST /api/auth/token` → Authentication (JWT)
* `POST /api/login-attempt` → Send login data
* `GET /api/dashboard/stats` → Dashboard stats
* `GET /api/dashboard/logs` → Logs with filters
* `POST /api/simulate` → Run attack simulation
* `POST /api/ip/block/{ip}` → Block IP
* `PUT /api/config` → Update thresholds
* `GET /api/export/csv` → Export logs
* `WS /ws/logs` → Real-time logs

---

## ⚡ Quick Start

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Run Server

```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open Dashboard

```
http://localhost:8000
```

**Login Credentials:**

* Username: admin
* Password: admin123

---

## 🤖 Machine Learning

* **Algorithm:** Isolation Forest
* **Purpose:** Detect anomalies in login behavior
* **Scoring:**

  * 0 → Safe
  * 100 → High Risk

---

## 📊 Simulation Modes

* **Brute Force** → Multiple failed attempts from one IP
* **Distributed Attack** → Multiple IPs targeting one account
* **Credential Stuffing** → One IP attacking multiple accounts
* **Mixed Mode** → Combination of all attacks

---

## 🔒 Security Features

* JWT-based authentication
* Rate limiting
* Password hashing (bcrypt)
* Configurable detection thresholds

---

## 📁 Project Structure

```
BruteShield/
├── backend/
├── frontend/
├── requirements.txt
├── start.bat
└── README.md
```

---

## 🎯 Purpose

This project is built for **educational and defensive cybersecurity purposes**, helping learners understand how modern SOC systems detect and respond to authentication-based attacks.

---

## ⭐ Conclusion

BruteShield demonstrates how AI and real-time monitoring can be combined to build a powerful and intelligent brute force detection system. It provides hands-on experience with cybersecurity concepts, machine learning, and full-stack development.

---
