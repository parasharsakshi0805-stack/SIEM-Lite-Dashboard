# SIEM-lite Dashboard

A lightweight Security Information and Event Management (SIEM) tool that ingests security logs, buffers them through Redis for high-throughput writes, and flags anomalies using two complementary detection methods: a real-time sliding-window algorithm and an Isolation Forest ML model.

Built as a portfolio project demonstrating full-stack development with a security and machine learning focus.

## Architecture

```
Client / Log Source
        |
        v
  FastAPI (ingest endpoints)
        |
        v
    Redis Queue  <-- fast write buffer
        |
        v
  Background Worker (flushes every 5s)
        |
        +--> PostgreSQL (persisted logs)
        |
        +--> Sliding-Window Detector (DSA, deque-based, real-time)
        |
        +--> Isolation Forest Model (ML, batch-scored)
        |
        v
  Anomalies table (PostgreSQL)
        |
        v
  React Dashboard (charts, filters, live anomaly feed)
```

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, Alembic
- **Database:** PostgreSQL
- **Queue/Buffer:** Redis (via Docker)
- **ML:** scikit-learn (Isolation Forest), pandas
- **Frontend:** React (Vite), Recharts, Axios

## Features

- Single and batch log ingestion via REST API
- Redis-buffered write pipeline for high-throughput ingestion
- Real-time sliding-window anomaly detection (volume-based, per source IP)
- Isolation Forest ML-based anomaly detection (pattern-based)
- Live dashboard: severity breakdown, event type breakdown, filterable/searchable log table, anomaly feed
- See [docs/detector-comparison.md](docs/detector-comparison.md) for design rationale behind using two detection methods

## Setup

### Prerequisites

- Python 3.11+
- Node.js (LTS)
- PostgreSQL
- Docker Desktop (for Redis)

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

Create a `.env` file in `backend/`:

```
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/siem_lite
REDIS_URL=redis://localhost:6379/0
```

Create the database:

```sql
CREATE DATABASE siem_lite;
```

Run migrations:

```bash
alembic upgrade head
```

Start Redis:

```bash
docker run -d --name siem-redis -p 6379:6379 redis
```

Train the ML model (needs some seed data first — see below):

```bash
python train_model.py
```

Run the API server:

```bash
uvicorn main:app --reload
```

Run the background worker (separate terminal):

```bash
python worker.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173`

### Seed sample data (optional)

```bash
python seed_data.py
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Health check |
| POST | /logs/ingest | Ingest a single log |
| POST | /logs/ingest/batch | Ingest multiple logs |
| GET | /logs | Query logs (supports severity, event_type filters, pagination) |
| GET | /logs/stats | Aggregated stats (severity/event type breakdowns, top IPs) |
| GET | /anomalies | List detected anomalies from both detectors |

## Project Status

Built as part of a structured multi-week build plan, covering ingestion pipeline design, DSA-based real-time detection, and applied ML for anomaly detection.