# Developer Guide

## Architecture

The application follows a layered Flask structure:

- `domain`: investigation entities and pure domain services.
- `application`: DTOs, service orchestration, and ports.
- `infrastructure`: database, storage, plugins, AI providers, security, logging.
- `presentation`: web templates, static assets, error handling.
- `api/v1`: stable REST API.
- `features`: business-capability composition modules used by transports.

API handlers obtain cases, evidence, timeline, and AI capabilities from
`app.extensions["cyberinvestigator_features"]`. New transport code must not
construct repositories or storage adapters directly. Background work is
submitted through `cyberinvestigator_job_dispatcher`; the current adapter is
non-durable and must not be treated as an evidence-isolation boundary.

The authoritative architecture, security boundaries, responsive standards, and
incremental roadmap are documented in
[`enterprise-foundation.md`](enterprise-foundation.md). Architectural decisions
are recorded in [`adr/`](adr/).

Repository-wide coding, API, logging, error, testing, documentation, Git,
security-review, performance, accessibility, and Definition of Done
requirements are normative in
[`engineering-standards.md`](engineering-standards.md). The contribution
workflow and local quality gate are in [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

Reusable tokens, components, icons, state patterns, and breakpoint contracts
are documented in [`design-system.md`](design-system.md).

Zero Trust controls, evidence quarantine, authorization, API protection,
secrets, audit events, monitoring, and the future isolated-analysis boundary
are documented in [`security-architecture.md`](security-architecture.md).

Shared viewport tiers and adaptive component behavior are documented in
[`responsive-framework.md`](responsive-framework.md).

Global hierarchy, lifecycle grouping, breadcrumbs, contextual navigation,
role-based discovery, and search are documented in
[`information-architecture.md`](information-architecture.md).

New modules must preserve the dependency direction and definition of done in
that foundation. Do not add unrelated endpoints to the central API blueprint or
new page behavior to the shared JavaScript bundles.

## Security Expectations

- Use SQLAlchemy expressions and bound parameters for database access.
- Never return stack traces, filesystem paths, secrets, or raw provider errors to clients.
- Add CSRF tokens to browser-originating mutating requests.
- Prefer `textContent` over `innerHTML` for dynamic UI text.
- Keep provider integrations optional and fallback-safe.

## Testing

Run:

```powershell
python -m ruff check src tests
python -m ruff format --check src tests
python -m compileall -q src
python -m pytest
```

Add focused tests for each new endpoint, domain rule, and security control.
