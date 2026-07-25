# Deployment guide

## Environments

CyberInvestigator supports explicit `development`, `testing`, and `production`
profiles through `CYBERINVESTIGATOR_ENV`. Production startup fails closed unless
`SECRET_KEY`, `DATABASE_URL`, `TRUSTED_HOSTS`, and a unique
`DEFAULT_ADMIN_PASSWORD` are supplied.

Copy `.env.example` only as a local template. Never commit `.env`. Production
secrets should be injected by the deployment platform or secret manager.

Minimum production configuration:

- `CYBERINVESTIGATOR_ENV=production`
- `SECRET_KEY`
- `DATABASE_URL`
- `TRUSTED_HOSTS`
- `DEFAULT_ADMIN_PASSWORD`
- `POSTGRES_PASSWORD` when using Compose
- `SESSION_COOKIE_SECURE=true`
- `CSRF_ENABLED=true`
- `SECURITY_HEADERS_ENABLED=true`
- persistent `INSTANCE_PATH`, `UPLOAD_ROOT`, `REPORTS_FOLDER`, `LOGS_FOLDER`,
  and `BACKUP_ROOT`

## Container deployment

The production image is multi-stage, runs as UID/GID `10001`, contains only the
installed application and WSGI entry point, and uses the readiness endpoint for
health checks. Compose removes Linux capabilities, prevents privilege
escalation, uses a read-only root filesystem, provides a non-executable
temporary filesystem, binds the application port to loopback, and stores
persistent application and database data in named volumes.

Before starting Compose:

1. Populate deployment-managed secrets.
2. Set trusted public hostnames.
3. For the first Compose boot, allow additive schema creation. After bootstrap,
   set `DATABASE_AUTO_CREATE_SCHEMA=false` and use the reviewed migration path.
4. Ensure persistent volumes are encrypted and backed up.
5. Place TLS termination in front of the loopback application port.

Run:

```powershell
docker compose config --quiet
docker compose build
docker compose up -d
./scripts/verify-deployment.ps1 -BaseUrl http://127.0.0.1:8000
```

The repository does not include a cloud-specific deployment adapter, so it does
not claim that an image published by CI has been deployed to a runtime.

## Database and evidence storage

PostgreSQL is recommended for production. SQLite remains suitable for local or
small offline investigations. Quarantine, reports, backups, and database data
must live on restricted persistent encrypted volumes. Quarantine must never be
mounted as executable or served by a web server.

The application performs only its existing additive startup migrations.
Destructive migrations require a separately reviewed maintenance workflow and
rollback plan.

## CI and release delivery

`.github/workflows/ci.yml` runs:

- Ruff lint and formatting checks
- Python compilation
- Complete tests with a retained JUnit artifact
- `pip-audit` dependency scanning
- Bandit static application security scanning
- GitHub CodeQL
- Production container build

`.github/workflows/release.yml` is tag/manual initiated, uses protected GitHub
environments, publishes an immutable GHCR image, and produces build provenance
attestation. The workflow explicitly stops at the delivery artifact when no
environment deployment adapter is configured.

Dependabot monitors Python, GitHub Actions, and Docker dependencies.

## Verification and rollback

`scripts/verify-deployment.ps1` checks live liveness and readiness responses.
Authenticated administrators can run deeper database, storage, audit-chain,
security-control, and release-metadata verification in the Deployment workspace.

Rollback uses immutable image redeployment:

1. Enable maintenance mode.
2. Create and verify a storage backup.
3. Select a recorded image digest.
4. Create an audited rollback plan.
5. Redeploy using the environment adapter.
6. Run deployment and evidence-integrity verification.

`scripts/rollback.ps1` is plan-only unless `-Apply` is explicitly provided.
Ending maintenance mode remains an operator decision after verification.

## Monitoring

Probe `/api/v1/health/live` for process liveness and
`/api/v1/health/ready` for dependency readiness. Collect structured logs from
the configured logs volume. Use the Observability, Storage, and Deployment
administration workspaces for measured runtime state.
