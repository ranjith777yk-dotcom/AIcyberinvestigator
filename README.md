# CyberInvestigator AI

CyberInvestigator AI is a Flask-based cyber investigation platform with case management, evidence custody, timelines, reports, plugin management, and fallback-safe AI assistance.

## Production Capabilities

- Case, evidence, timeline, report, plugin, and AI investigation workflows.
- Provider abstraction with optional OpenAI integration and local fallback behavior.
- IOC extraction, ATT&CK mapping, log/email/file analysis, hash analysis, threat scoring, and evidence correlation.
- SQLAlchemy persistence with indexes, relationships, constraints, transactions, and additive migration helpers.
- Secure headers, secure cookie configuration, CSRF protection, rate limiting, RBAC hooks, audit logging, and safe error responses.
- Health/readiness endpoints, metrics endpoint, admin overview, user/secret inventory endpoints.
- Docker, Docker Compose, CI, backup/recovery scripts, and environment-based configuration.

## Local Installation

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python run.py
```

Open `http://127.0.0.1:5000`.

## Configuration

Copy `.env.example` to `.env` for Docker deployments and set strong values for `SECRET_KEY`, database credentials, `TRUSTED_HOSTS`, and any provider API keys.

AI features continue to work in local fallback mode when `AI_API_KEY` is unavailable.

## Docker

```bash
cp .env.example .env
docker compose up --build
```

The app listens on `http://127.0.0.1:8000`.

## Health Checks

- `GET /api/v1/health/live`
- `GET /api/v1/health/ready`
- `GET /api/v1/monitoring/metrics` requires admin role.

## Backup And Recovery

SQLite/local instance backup:

```powershell
.\scripts\backup.ps1
```

Recover:

```powershell
.\scripts\recover.ps1 -BackupPath backups\cyberinvestigator-YYYYMMDD-HHMMSS
```

For PostgreSQL, use managed snapshots or `pg_dump` and restore alongside the persisted `instance` volume.
