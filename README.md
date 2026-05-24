# SHIELDX — Autonomous AI SOC Analyst Platform

SHIELDX is an advanced AI-powered Security Operations Center (SOC) analyst platform that autonomously detects cyber threats, reconstructs attack chains, suppresses false positives, scores behavioral personas, and executes orchestrated playbooks — all in real time.

---

## ✨ Features

- **Advanced Behavioral Persona Engine**: Continuously builds behavioral fingerprints for users and devices, alerting on deviations in time, actions, and peer groups.
- **Automated Triage & SLA Tracking**: Automatically assesses risk and priority of multi-stage incidents, assigning severity and tracking analyst SLA breach times.
- **Zero-Day ML Detection Pipeline**: Background PyTorch and HDBSCAN ML queues ingest logs to detect anomalies that standard deterministic rules miss.
- **False Positive Suppression Engine**: Uses contextual baseline evaluation to suppress alerts automatically if they match known benign scheduled jobs or IPs.
- **Futuristic Dark Dashboard**: Rich visual experience with animated circular risk scores, stacked threat velocity charts, active alerts trackers, and SOAR mitigation panels.
- **Real-time Log Feed**: Monospaced scrolling terminal logging telemetry events streamed instantly via WebSockets.
- **Threat Topology Graph**: Interactive force-directed link canvas physics showing users, IP geolocations, and affected devices.
- **AI Copilot Chat**: Analysts chatbot helper with context-aware queries grounded in the current alerts database.
- **Orchestrated Mitigations**: Active response action audits (block IPs, lock accounts, force MFA reset, process containment).
- **Threat Simulator**: Instant mock simulations for Brute Force, Malware execution, Insider threats, API abuses, and Slow-Drip Exfiltrations.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.9+, FastAPI, aiosqlite, SQLite database, WebSockets.
- **Machine Learning**: PyTorch, HDBSCAN, Scikit-learn, UMAP.
- **Frontend**: React, Vite, TypeScript, TailwindCSS, Zustand state, Recharts, Motion, React Force Graph, Lucide Icons.
- **Deployment**: Docker Compose.

---

## 🚀 Quick Start

### Prerequisites
Make sure you have **Docker** and **Docker Compose** installed on your system.

### Steps to Run
1. In the project root, copy the environment configuration:
   ```bash
   cp .env.example .env
   ```
2. Fire up the multi-container environment:
   ```bash
   docker compose up --build
   ```
3. Open your browser and navigate to:
   **[http://localhost:5173](http://localhost:5173)**

---

## 📂 Project Structure

```
AI_Agent/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI lifecycles and WebSockets
│   │   ├── api/                 # Endpoint routers (alerts, incidents, simulator)
│   │   ├── core/                # Settings configs loaders
│   │   ├── database/            # SQLite aiosqlite queries wrappers
│   │   ├── models/              # Pydantic schemas declarations
│   │   └── services/            # Detection, false positive, simulator, and ML services
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/          # Sidebar, Skeleton loaders, Threat simulator panel
│   │   ├── pages/               # Dashboard, Incidents lists, Detail view, Threat Graph
│   │   ├── hooks/               # useWebSocket listeners hooks
│   │   ├── services/            # fetch api clients
│   │   └── stores/              # Zustand global states store
│   └── Dockerfile
└── docker-compose.yml
```
