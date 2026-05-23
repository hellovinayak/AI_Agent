# SentinelAI — Autonomous AI SOC Analyst Platform

SentinelAI is an AI-powered Security Operations Center (SOC) analyst platform that autonomously detects cyber threats, reconstructs attack chains, suppresses false positives, and executes orchestrated playbooks — all in real time.

---

## ✨ Features

- **Futuristic Dark Dashboard**: Rich visual experience with animated circular risk scores, stacked threat velocity charts, active alerts trackers, and SOAR mitigation panels.
- **Real-time Log Feed**: monospaced scrolling terminal logging telemetry events streamed instantly via WebSockets.
- **Correlated Incidents**: Alerts automatically grouped into security incidents using heuristics with detailed vertical attack timelines.
- **Threat Topology Graph**: Interactive force-directed link canvas physics showing users, IP geolocations, and affected devices.
- **AI Copilot Chat**: analysts chatbot helper with context-aware queries grounded in the current alerts database.
- **Orchestrated Mitigations**: Active response action audits (block IPs, lock accounts, force MFA reset, process containment).
- **Threat Simulator**: Instant mock simulations for Brute Force, Malware execution, Insider threats, and API abuses.
- **Autonomous AI Fallback**: Complete, highly realistic pre-configured mock threat explanations requiring NO API keys.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.11, FastAPI, aiosqlite, SQLite database, WebSockets.
- **Frontend**: React, Vite, TypeScript, TailwindCSS, Zustand state, Recharts, Motion, React Force Graph, Lucide Icons, React Hot Toast.
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
   **[http://localhost:3000](http://localhost:3000)**

---

## 📂 Project Structure

```
AI/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI lifecycles and WebSockets
│   │   ├── api/                 # Endpoint routers (alerts, incidents, simulator)
│   │   ├── core/                # Settings configs loaders
│   │   ├── database/            # SQLite aiosqlite queries wrappers
│   │   ├── models/              # Pydantic schemas declarations
│   │   └── services/            # Detection, false positive, simulator, and AI services
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/          # Sidebar, Skeleton loaders, Threat simulator panel
│   │   ├── pages/               # Dashboard, Incidents lists, Detail view, Threat Graph, Copilot
│   │   ├── hooks/               # useWebSocket listeners hooks
│   │   ├── services/            # fetch api clients
│   │   ├── stores/              # Zustand global states store
│   │   └── types/               # TypeScript models schemas
│   ├── index.html
│   ├── nginx.conf               # SPA routing Nginx proxy
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```
