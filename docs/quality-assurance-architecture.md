# Testing, quality assurance, and security validation

## Evidence model

The administrator-only quality workspace at `/admin/quality` reads generated
artifacts from `instance/quality`. It never estimates results from workflow
definitions. Missing or malformed files are shown as unavailable. Its API is
`GET /api/v1/admin/quality`.

| File | Producer | Display |
| --- | --- | --- |
| `junit.xml` | pytest | suite totals, duration, failures, skips |
| `coverage-summary.json` | pytest-cov | measured code coverage |
| `accessibility-summary.json` | browser checks | executed accessibility scope |
| `performance-summary.json` | browser gate | observed samples and latency budget |
| `bandit-report.json` | Bandit | source security findings |
| `dependency-audit.json` | pip-audit | dependency findings |

CI publishes core, browser, and security evidence as retained artifacts. A
future authenticated CI connector may import those artifacts into a running
environment; until then, external run history is explicitly unavailable.

## Layered validation

- Unit tests isolate domain, application, and infrastructure behavior.
- Integration tests exercise persistence, APIs, RBAC, evidence isolation, AI
  fallback behavior, and audited operational controls.
- Functional and architecture suites validate workflows, UI surfaces,
  dependencies, and delivery contracts.
- Chromium E2E tests exercise desktop, laptop, tablet, and mobile viewports.
- Browser checks enforce basic keyboard focus, semantic landmarks, responsive
  overflow, and a measured readiness-endpoint latency budget.
- Bandit, pip-audit, CodeQL, and container gates validate release security.

The accessibility check is a basic automated semantic and keyboard check, not a
WCAG conformance certification. The performance gate is a CI-local endpoint
budget, not a production capacity benchmark.

## Isolation and release control

CI selects the `testing` profile and an in-memory SQLite database. Tests must
not receive production credentials, database URLs, or evidence mounts.
Generated evidence remains under the ignored instance directory and is retained
by CI for 14 days.

Container publication depends on core, browser, dependency, SAST, and CodeQL
jobs. Releases additionally use a protected GitHub environment.
`POST /api/v1/admin/deployments/release-approvals` records an administrator
decision only when immutable revision metadata exists. The decision is audited;
it neither deploys nor bypasses the external environment gate.

## Local execution

```powershell
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
python -m pytest tests/unit tests/integration tests/functional tests/architecture
python -m pytest tests/e2e
python -m ruff check .
python -m bandit -r src -x tests -lll -iii
python -m pip_audit
```
