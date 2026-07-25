# CyberInvestigator Enterprise Foundation

## Purpose

CyberInvestigator is an AI-assisted digital forensics and incident response platform. Its primary product workflow is:

1. Authenticate and authorize an investigator.
2. Create or select an investigation case.
3. Ingest evidence as untrusted bytes.
4. Preserve provenance, custody metadata, and a content hash.
5. Analyze evidence through bounded adapters.
6. Correlate artifacts, timeline events, and AI findings.
7. Produce traceable recommendations and professional reports.

Every module should strengthen this workflow. Features that cannot identify their case scope, permission, audit event, failure behavior, and data owner are not ready for implementation.

## Current Architecture Assessment

The repository has the right high-level package boundaries:

| Layer | Responsibility | Current state |
| --- | --- | --- |
| `domain` | Investigation concepts and deterministic analysis rules | Strong service coverage; repository protocols still reference persistence models |
| `application` | Use-case orchestration, DTOs, and ports | Present for cases, evidence, and timeline; some services import SQLAlchemy and infrastructure time/model helpers |
| `infrastructure` | Database, evidence storage, AI providers, plugins, security, logging | Mature but several operational concerns are concentrated in large modules |
| `api/v1` | Stable HTTP contract | Versioned and tested; the primary blueprint is too large for safe long-term ownership |
| `presentation` | Server-rendered workspaces and progressive JavaScript | Functional and accessible; shared JavaScript and legacy CSS contain multiple feature domains |
| `shared` | Cross-cutting types and exceptions | Appropriately small |

The application factory is the composition root. Runtime integrations are registered through `app.extensions`; this is the compatibility seam to preserve while modules are extracted.

### Existing strengths

- Versioned API routes and an application factory.
- Explicit RBAC permissions in addition to role checks.
- CSRF validation for mutating browser requests.
- Server-side session records, lockout behavior, and audit logging.
- Atomic evidence writes with SHA-256 calculation.
- Case-scoped evidence paths and hardened deletion compensation.
- Soft deletion of evidence metadata while retaining custody bytes.
- Provider abstractions and fallback-safe AI behavior.
- Functional, integration, unit, RBAC isolation, and security tests.
- Additive database migration behavior.

### Priority inconsistencies

1. `api/v1/blueprint.py` owns unrelated endpoints and serialization logic in one module.
2. `dashboard.js` and `dashboard_extras.js` share global scope and mix multiple workspaces.
3. `dashboard_polish.css` contains product-wide, page-specific, responsive, and theme rules together.
4. Domain repository protocols expose SQLAlchemy models, and application services import infrastructure models.
5. Request validation and response serialization are repeated across API handlers.
6. Broad exception catches are sometimes necessary at trust boundaries, but their policy is not documented consistently.
7. OpenAPI output discovers routes but does not yet describe request/response schemas or permission requirements.
8. Evidence is quarantined logically, but analysis is still in-process rather than isolated.
9. Background work uses an in-process executor, which is unsuitable for durable or hostile evidence workloads.
10. Frontend assets depend on global functions and load broadly instead of being owned by feature modules.

These are extraction targets, not reasons for a rewrite.

## Dependency Rules

The intended dependency direction is:

```text
presentation / api
        |
        v
   application  ---> shared
        |
        v
      domain

infrastructure implements application/domain ports
composition root wires all concrete dependencies
```

Rules for new code:

- `domain` must not import Flask, presentation, API, or HTTP concerns.
- `application` must not import Flask, presentation, or API concerns.
- Infrastructure adapters may depend on application ports and domain contracts.
- API and presentation modules may call application services, but should not implement investigation rules.
- Database transactions are owned by a use case or repository boundary, never by template or browser code.
- Cross-module communication uses DTOs or explicit ports, not another module's private helpers.
- Existing imports that violate the ideal direction should be removed incrementally when that feature is touched.

The architecture test enforces only boundaries the current repository already satisfies. Stricter rules should be enabled after the relevant extraction, not before it.

## Module Contract

Every new or extracted feature module should define:

- one clear business capability;
- input DTOs and validation;
- output DTOs;
- application service or query handler;
- repository/provider ports;
- concrete infrastructure adapters;
- API handlers that translate HTTP to DTOs;
- permission requirements;
- audit events for meaningful state changes;
- stable error codes/messages;
- unit and integration tests;
- frontend entry point only when a UI is required.

Suggested API extraction order:

```text
api/v1/
  cases.py
  evidence.py
  timeline.py
  reports.py
  ai.py
  plugins.py
  operations.py
  admin.py
  serializers/
  validation/
```

Routes and response shapes must remain unchanged during extraction.

## Evidence Trust Boundary

Uploaded evidence is hostile until proven otherwise.

### Required lifecycle

```text
request stream
  -> size enforcement
  -> quarantine write + SHA-256
  -> immutable custody metadata
  -> queued analysis request
  -> isolated analyzer
  -> normalized findings
  -> correlation / AI
  -> report
```

### Invariants

- Never execute, import, render, or serve evidence directly from its original filename.
- Treat MIME type and extension as claims, not proof.
- Use generated storage identifiers and canonical root checks.
- Preserve original bytes after registration; derived artifacts use separate identities.
- Hash while streaming and compare hashes when moving between trust zones.
- Bound decompression, recursion depth, extracted size, file count, CPU time, memory, and output.
- Do not give analysis workers application credentials or unrestricted network access.
- AI providers receive minimized, policy-approved derived content—not raw evidence by default.
- Every analysis result records analyzer identity/version, source evidence hash, timestamps, status, and failure reason.
- Evidence deletion remains a custody operation requiring explicit retention policy and audit records.

### Isolation roadmap

The current analyzers are bounded but in-process. The future adapter should implement an `AnalysisRunner` port and execute in an ephemeral container or restricted worker with:

- read-only evidence mount;
- writable disposable output directory;
- no host filesystem access;
- network disabled by default;
- non-root user;
- syscall/capability restrictions;
- hard resource and wall-clock limits;
- signed/versioned analyzer image;
- structured result schema.

## Security Baseline

Each endpoint must have an explicit classification:

| Classification | Requirement |
| --- | --- |
| Public | Explicit allow-list entry, rate limit, no sensitive response |
| Authenticated | Active server-side session |
| Case scoped | Authentication plus ownership/tenant scope |
| Privileged | Named permission and audit event |
| Administrative | Admin permission, security audit, minimal response |

Additional standards:

- Deny by default when a permission mapping is missing for a mutating endpoint.
- Keep CSRF protection independent of RBAC.
- Return a request ID with sanitized errors.
- Avoid logging secrets, raw evidence, credentials, tokens, or AI prompts containing evidence.
- Use constant-time comparisons for tokens and hashes where relevant.
- Outbound provider URLs must be fixed or allow-listed to prevent SSRF.
- Plugin execution requires signature verification, resource limits, and an explicit capability policy.
- Production must fail startup for unsafe secrets or insecure cookie settings.

## Frontend Foundation

The frontend remains server-rendered with progressive JavaScript. A framework migration is not required.

### Ownership

- `base.html` owns the global shell only.
- Page templates own semantic structure, not shared component styling.
- Shared primitives belong in small component stylesheets.
- Feature behavior belongs in one feature entry point initialized through a `data-module` root.
- JavaScript must not execute feature API requests when its module root is absent.
- Dynamic untrusted content uses `textContent`; HTML rendering requires a reviewed sanitizer.

### Design tokens

New styles should consume semantic tokens rather than page-specific colors:

- surfaces: canvas, surface, raised, overlay;
- text: primary, secondary, disabled, inverse;
- borders: subtle, default, strong;
- intent: informational, success, warning, critical;
- spacing: 4, 8, 12, 16, 24, 32, 48;
- radii: 6, 8, 12, 16;
- motion: 120–200 ms for direct interaction, reduced-motion fallback.

Existing tokens should be consolidated gradually; do not mass-rewrite stable pages.

### Responsive behavior

Breakpoints express layout changes rather than scaled desktop UI:

- Mobile: one primary task, stacked filters, card/list table alternative, persistent access to primary action.
- Tablet: two-column summaries where useful, off-canvas navigation, touch targets of at least 44 px.
- Laptop: compact navigation, constrained content density, no horizontal page scroll.
- Desktop: multi-column operational context with a readable maximum content width.

Every interactive feature must remain available at every breakpoint.

### Accessibility

- WCAG 2.2 AA is the baseline.
- Preserve logical headings and landmarks.
- Provide visible focus and keyboard operation.
- Use native controls before ARIA.
- Announce asynchronous status without moving focus unexpectedly.
- Charts require a text summary or accessible label.
- Color never carries severity or status alone.

## API and Data Standards

- Preserve `/api/v1` route and response compatibility.
- Add schema-first request/response documentation before introducing `/api/v2`.
- Collection endpoints use consistent `items`, pagination, filtering, sorting, and error structures.
- Timestamps are UTC ISO 8601.
- Identifiers are opaque to clients.
- Mutations are idempotent where practical; long-running work returns a job identity.
- List endpoints enforce case ownership in the query, not after serialization.
- Expensive dashboard/read models may be cached by user scope and invalidated on mutation.

## Performance Standards

- One initial request per page module where a consolidated read model exists.
- Defer secondary widgets until the primary workflow is interactive.
- Paginate database-backed collections.
- Stream evidence uploads and AI output; never buffer large evidence in browser memory.
- Move durable analysis to a persistent queue before scaling beyond one process.
- Add database indexes from measured query plans, not assumptions.
- Set explicit timeouts and bounded retries for every provider call.
- Cache only authorization-scoped data and document invalidation.

## Testing and Delivery Gates

Required gates:

1. Ruff and formatting checks.
2. Unit tests for domain rules.
3. Integration tests for repositories, storage, providers, and transactions.
4. Functional tests for route contracts and critical workflows.
5. RBAC isolation tests for every case-scoped resource.
6. Security regression tests for CSRF, traversal, archive bombs, plugin boundaries, and redirect safety.
7. Accessibility and responsive browser checks when browser automation is introduced.
8. Backward-compatible OpenAPI diff before API releases.

No feature is complete without success, empty, loading, partial-failure, forbidden, and degraded-provider states.

## Incremental Roadmap

### Phase 0 — Foundation (current)

- Record architecture, trust boundaries, frontend standards, and delivery gates.
- Add non-breaking architecture checks.
- Preserve the application factory as the composition root.
- Compose cases, evidence, timeline, and AI through the feature registry.
- Route asynchronous submissions through the replaceable background-job port.
- Define the provider-neutral isolated-analysis contract.

### Phase 1 — Separate contracts from transport

- Introduce persistence-neutral domain records for case, evidence, and timeline repository protocols.
- Move SQLAlchemy exception translation into repository adapters.
- Centralize API validation, pagination, serialization, and error envelopes.
- Add permission metadata to generated OpenAPI operations.

### Phase 2 — Extract feature modules

- Split the API blueprint by capability without changing routes.
- Split shared JavaScript into case, evidence, timeline, reports, AI, settings, and admin entry points.
- Consolidate semantic CSS tokens and reusable primitives.
- Keep compatibility exports until callers migrate.

### Phase 3 — Durable analysis plane

- Add job and analysis-run ports.
- Introduce a durable queue and idempotent workers.
- Move forensic processing into isolated, resource-limited execution.
- Persist structured analyzer provenance and result schemas.

### Phase 4 — Operational maturity

- Add distributed rate limiting and shared session/cache infrastructure.
- Export structured audit logs and metrics.
- Add SLOs, tracing, backup verification, retention policy, and incident runbooks.
- Add software supply-chain controls and signed release artifacts.

## Definition of Done for Future Modules

A module is ready when:

- it reinforces the investigation workflow;
- its owner and dependency direction are clear;
- permissions and case scope are enforced server-side;
- evidence and AI trust boundaries are explicit;
- errors are safe and actionable;
- loading, empty, degraded, and responsive states exist;
- data access is bounded and observable;
- tests cover happy path, failure, and authorization isolation;
- routes and persisted data remain compatible unless a versioned migration is approved;
- documentation and operational impact are updated.
