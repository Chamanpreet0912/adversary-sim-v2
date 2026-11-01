# Adversary Emulation & Attack Simulation Platform

Safe, lab-scoped adversary emulation mapped to MITRE ATT&CK. Pick an adversary profile, run a simulated campaign,
and see which techniques your detection rules catch, miss, or have disabled. Toggle rules and re-run to measure improvement.

**Safety by design:** the engine never runs real exploits or payloads. Each technique only emits a synthetic telemetry
event. Targets are restricted to an allowlist (`LAB_TARGETS`), and write endpoints can require `API_KEY`.

## Stack
FastAPI, SQLite, vanilla JS dashboard, pytest, Docker.

## Run
    pip install -r requirements.txt
    uvicorn app.main:app --reload          # http://localhost:8000
    pytest -q
    docker build -t adversary-sim . && docker run -p 8000:8000 -e API_KEY=changeme adversary-sim

## API
GET /api/catalog | PATCH /api/rules/{id}?enabled= | POST /api/runs | GET /api/runs | GET /api/runs/{id} | GET /api/runs/{id}/report

## Deploy (Render, free tier)
1. Push this folder to GitHub.
2. Render, New, Web Service, connect the repo, Runtime: Docker.
3. Set env vars: `API_KEY` (any secret), `LAB_TARGETS` (optional). Deploy. Health check path: `/healthz`.
Note: free tier storage is ephemeral, so run history resets on redeploy. Use a Render disk or Postgres for persistence.

## Roadmap
Real-lab agents (Atomic Red Team / Caldera connectors), Sigma rule import, scheduled purple-team runs, PDF reports.

## Authentication
Users sign in at `/login`. Passwords are hashed (PBKDF2-SHA256, 200k rounds) and sessions use signed, expiring tokens. Five failed logins lock an account for a minute.

| Role | Can do |
|---|---|
| viewer (default for new sign-ups) | View results and reports |
| analyst | Also run simulations |
| admin | Also switch rules on or off and create users (`POST /api/users`) |

Environment variables: `ADMIN_USER` (default `admin`), `ADMIN_PASSWORD` (**set this**, otherwise a demo password is used), `SECRET_KEY` (random string so sessions survive restarts).
