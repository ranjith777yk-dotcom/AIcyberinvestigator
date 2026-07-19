# Deployment Guide

## Minimum Production Settings

Set:

- `CYBERINVESTIGATOR_ENV=production`
- `SECRET_KEY`
- `DATABASE_URL`
- `TRUSTED_HOSTS`
- `SESSION_COOKIE_SECURE=true`
- `CSRF_ENABLED=true`
- `SECURITY_HEADERS_ENABLED=true`
- `USER_ROLES`

## Database

PostgreSQL is recommended for production. SQLite is suitable for local development and small offline investigations.

The application runs additive index migrations on startup. Destructive migrations should be handled with an external migration tool during planned maintenance.

## Secrets

Provide secrets through the runtime environment or a platform secret manager. `/api/v1/admin/secrets` reports presence only and never exposes values.

## Monitoring

Probe `/api/v1/health/live` for process liveness and `/api/v1/health/ready` for database readiness. Collect logs from `instance/logs/cyberinvestigator.log` and `instance/logs/audit.log`.
