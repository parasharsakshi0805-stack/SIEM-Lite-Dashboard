# SIEM-Lite Dashboard

A lightweight Security Information and Event Management (SIEM) tool that ingests security logs, buffers them through Redis for high-throughput writes, and flags anomalies using two complementary detection methods: a real-time sliding-window algorithm and an Isolation Forest ML model.

Built as a portfolio project demonstrating full-stack development with a security and machine learning focus — including production-grade hardening: secret management, rate-limited authentication, httpOnly cookie sessions, CORS enforcement, input validation, and CI.

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
  React Dashboard (stat cards, trend chart, severity/event/IP breakdowns, live anomaly feed)
```

In production, the React frontend is compiled to static assets and served by nginx (not the Vite dev server), with the backend reachable only through explicitly allowed origins.

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, Alembic
- **Database:** PostgreSQL
- **Queue/Buffer:** Redis (via Docker)
- **ML:** scikit-learn (Isolation Forest), pandas
- **Frontend:** React (Vite), Recharts, Axios
- **Auth:** JWT via httpOnly cookies, bcrypt password hashing
- **CI:** GitHub Actions (backend test suite on every push)
- **Production serving:** nginx (multi-stage Docker build)

## Features

- Single and batch log ingestion via REST API, with a hard cap on batch size to prevent overload
- Redis-buffered write pipeline for high-throughput ingestion
- Real-time sliding-window anomaly detection (volume-based, per source IP)
- Isolation Forest ML-based anomaly detection (pattern-based)
- Live dashboard: summary stat cards (total logs, active anomalies, critical events, unique source IPs), 24-hour log volume trend, interactive severity breakdown, event type breakdown, top source IPs, filterable/searchable log table, anomaly feed
- See [docs/detector-comparison.md](docs/detector-comparison.md) for design rationale behind using two detection methods

## Security

- **Authentication:** JWT stored in an `httpOnly` cookie (not accessible to JavaScript), rather than browser storage — mitigates token theft via XSS
- **Rate limiting:** login is capped at 5 attempts/minute per IP (via `slowapi`) to prevent brute-force attacks
- **CORS:** explicit origin allow-list via `CORS_ORIGINS`, not wildcarded
- **Input limits:** `/logs` and `/anomalies` cap `limit` at 500; `/logs/ingest/batch` caps batch size at 1000
- **Password hashing:** bcrypt via `passlib`
- **Secrets:** managed via environment variables, excluded from version control; see [Configuration](#configuration) below

> **Before deploying publicly:** HTTPS is not yet configured. The cookie's `secure` flag must be set to `true` (via `COOKIE_SECURE=true`) once TLS termination is in place — until then, the cookie is only safe for local/HTTP testing.

## Screenshots

![Dashboard overview](docs/screenshots/dashboard-overview.png)
![Anomalies detected](docs/screenshots/anomalies-detected.png)
![System Logs](docs/screenshots/system-logs.png)

## Configuration

This project requires two local `.env` files — one in the project root and one in `backend/` — to hold database, cache, and signing-key configuration. Neither is included in this repository, and neither should ever be committed; both are excluded via `.gitignore`.

Generate a strong signing key locally with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Refer to `docker-compose.yml` and `backend/database.py` / `backend/auth.py` for the exact environment variable names each service expects.

## Setup

### Prerequisites

- Docker Desktop (recommended for running the full stack)
- (Optional, for manual setup) Python 3.11+, Node.js (LTS), PostgreSQL

### Running with Docker Compose — Development

Runs the frontend via Vite's dev server with hot reload, on port `5173`.

```bash
docker compose up -d --build
```

Visit `http://localhost:5173`. The API is available at `http://localhost:8000`.

### Running with Docker Compose — Production

Serves the compiled frontend via nginx on port `80`.

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Visit `http://localhost`.

### Manual Local Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
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

### Create a user

```bash
python create_user.py
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Health check |
| POST | /auth/login | Log in, sets httpOnly session cookie (rate-limited: 5/min) |
| POST | /auth/logout | Clears the session cookie |
| GET | /auth/me | Returns the current authenticated user |
| POST | /logs/ingest | Ingest a single log |
| POST | /logs/ingest/batch | Ingest multiple logs (max 1000 per request) |
| GET | /logs | Query logs (supports severity, event_type filters, pagination; max 500 per request) |
| GET | /logs/stats | Aggregated stats (severity/event type breakdowns, top IPs, summary counts) |
| GET | /logs/stats/timeline | Hourly log volume for the last N hours (default 24, max 168) |
| GET | /anomalies | List detected anomalies from both detectors (max 500 per request) |

## CI

Every push to `main` runs the backend test suite automatically via GitHub Actions (`.github/workflows/ci.yml`).

## Project Status

Built as part of a structured multi-week build plan, covering ingestion pipeline design, DSA-based real-time detection, applied ML for anomaly detection, and production security hardening (secrets management, authentication, rate limiting, CORS, CI).

### Roadmap

- [x] Secrets rotation and environment-based configuration
- [x] Production frontend build (nginx, multi-stage Docker)
- [x] CORS enforcement
- [x] Login rate limiting
- [x] httpOnly cookie-based authentication
- [x] Input/query limits
- [x] CI pipeline
- [ ] HTTPS / reverse proxy
- [ ] Monitoring, logging, and automated backups
- [ ] Dependency pinning and repo cleanup