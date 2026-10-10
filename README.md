# VulnCentral Intelligence — Full-Stack (Frontend + API + Cloud config)

```
frontend/   Vite + vanilla JS dashboard (sample data fallback)
backend/    Node.js 20 + Express + SQLite (better-sqlite3)
Dockerfile  one container: builds the frontend, serves it and the API
docker-compose.yml, render.yaml, .env.example
```

## What is implemented and tested
- REST API: `/api/health, /api/bootstrap, /api/vulnerabilities, /api/vulnerabilities/:id, /api/assets, /api/tasks (PATCH status), /api/events, /api/sources, /api/assistant/query`
- SQLite database seeded with the sample records on first start
- Frontend loads from the API and falls back to built-in sample data if the API is unreachable
- Remediation status changes are saved through the API
- NVD and CISA KEV parsers (normalization, upsert, keyword-based *possible* asset matching) — **tested with mock payloads only**

## Not verified in the build environment
- Live downloads from NVD and CISA (no internet access to those hosts here). Run an ingest yourself and check **Data Source Status**: it shows *Connected* only after a successful ingest and *Failed to update* with the error otherwise.
- The optional LLM call (`ANTHROPIC_API_KEY`). Without a key the assistant is rule-based over database records.
- Docker build and cloud deployment (config provided, not executed here).

## Run locally (no Docker)
```bash
cd backend && npm install && npm start          # API on :8080
cd frontend && npm install && npm run dev       # UI on :5173 (proxies /api to :8080)
```
Trigger ingestion: `cd backend && npm run ingest`  (needs internet)

## Run with Docker
```bash
cp .env.example .env     # set ADMIN_TOKEN
docker compose up --build
# open http://localhost:8080
curl -X POST localhost:8080/api/admin/ingest -H "Authorization: Bearer <ADMIN_TOKEN>"
```

## Deploy to the cloud
| Platform | Steps |
|---|---|
| **Render** | Push to GitHub → New → Blueprint → select repo (uses `render.yaml`, persistent disk at `/data`). |
| **Railway / Fly.io** | Deploy the root `Dockerfile`; attach a volume mounted at `/data`; set env vars from `.env.example`. |
| **AWS** | Build image → push to ECR → run on App Runner or ECS Fargate with an EFS volume at `/data`. |
| **Azure** | Push to ACR → Azure Container Apps with an Azure Files volume at `/data`. |
| **Google Cloud Run** | Works, but its filesystem is not persistent: move the database to Cloud SQL (PostgreSQL) first. |

SQLite needs one instance with a persistent disk. For multi-instance or managed scaling, replace `backend/src/db.js` with PostgreSQL (the SQL is simple and portable).

## Security notes before real use
- No user authentication exists (by project scope). Reads and task updates are open; only `/api/admin/ingest` is token-protected. Put the app behind a login/VPN or add authentication before exposing real institutional data.
- Never commit `.env`. Keep API keys on the server only.
- Set `CORS_ORIGIN` if the frontend is hosted on a different domain (and build it with `VITE_API_URL=https://your-api`).

## Architecture
External sources (NVD, CISA KEV) → `ingest.js` (collect, validate, normalize) → SQLite registry → Express API → dashboard, assistant, tasks, reports.
