# CyberInvestigator Engineering Standards

Status: normative  
Applies to: all current and future modules  
Compatibility rule: adopt incrementally; do not break supported routes, APIs,
authentication, RBAC, evidence records, or business workflows.

## 1. Engineering principles

1. Preserve evidence integrity and user trust before optimizing convenience.
2. Treat every external value and uploaded file as untrusted.
3. Organize behavior by investigation capability, with transport and framework
   code at the boundary.
4. Prefer explicit contracts, small cohesive changes, and reversible migration.
5. Build observability, accessibility, testability, and failure behavior into
   the initial implementation.
6. Never execute uploaded evidence in the web application process.

The project currently has a sound layered direction and shared feature
registry, but enforcement is uneven. Historical endpoints use more than one
error envelope, some permission coverage was implicit, logging is primarily
text-based, and CI previously ran tests without lint, formatting, compilation,
or architectural policy checks. These are migration targets, not justification
for breaking existing clients.

## 2. Architecture contract

Dependency direction is:

```text
presentation / api -> application / features -> domain
                              |
                              v
                    infrastructure adapters
```

- `domain` contains framework-independent entities, value objects, and rules.
- `application` contains use cases, DTOs, ports, and transaction orchestration.
- `features` composes a business capability for transports.
- `infrastructure` implements persistence, storage, providers, security,
  queues, logging, and integrations.
- `presentation` and `api/v1` translate HTTP input and output only.
- Routes obtain capabilities from the application feature registry. They do
  not instantiate repositories, storage adapters, or AI providers.
- Cross-feature calls use an application service or declared port, not imports
  into another feature's presentation internals.
- Shared code must have two proven consumers. Otherwise keep it within its
  feature.
- External providers sit behind typed ports with explicit timeout, retry,
  cancellation, and safe fallback behavior.
- Long-running or risky analysis crosses the job-dispatch boundary. The
  in-process dispatcher is not an isolation or durability boundary.

Record an ADR under `docs/adr/` when changing a trust boundary, dependency
direction, persistence model, public contract, queue model, or major shared
abstraction.

## 3. Coding standards

### Python

- Target the Python version declared by project metadata and CI.
- Ruff is authoritative for lint and formatting; do not add local style
  exceptions without a documented reason.
- Add type annotations to new public functions and application boundaries.
- Prefer immutable dataclasses or explicit DTOs for boundary data.
- Use timezone-aware UTC timestamps and stable opaque identifiers.
- Keep functions cohesive; separate parsing, policy, orchestration, and I/O.
- Catch specific exceptions. Broad exception handling is allowed only at a
  process or transport boundary, where it must log safely and return a stable
  failure contract.
- Do not use `print` in application code. Use the configured logger.
- Do not introduce hidden global mutable state.

### Frontend

- Use shared design tokens, primitives, responsive utilities, and icon
  conventions before adding one-off styles.
- Bind page behavior through explicit module hooks; do not grow a global script
  with unrelated page logic.
- Use semantic HTML and progressive enhancement. Dynamic text uses safe DOM
  APIs, never interpolated untrusted HTML.
- Every asynchronous surface defines loading, success, empty, error, retry,
  and permission-denied behavior.
- Avoid viewport-dependent network duplication and unnecessary re-rendering.

### Dependencies and configuration

- Prefer the standard library and existing dependencies.
- New dependencies require a maintenance, license, security, size, and
  alternatives review.
- Configuration is validated at startup. Secrets come from the approved secret
  source, never source control or client bundles.
- Pin deployable dependencies through the project's chosen lock or constraint
  mechanism and review vulnerability alerts.

## 4. API standards

- Preserve `/api/v1` routes and semantics. Additive fields are preferred.
  Breaking contracts require a new version plus a migration and deprecation
  plan.
- Define input schemas, content type, size limits, authorization permission,
  response schema, status codes, and audit behavior for every endpoint.
- Mutating endpoints require CSRF protection when session-authenticated and an
  explicit entry in the central permission policy.
- Collection endpoints use bounded pagination, deterministic ordering, and
  validated filters. Never expose unbounded evidence or audit collections.
- Use UTC ISO 8601 timestamps, opaque IDs, and documented enums.
- Use correct HTTP semantics and idempotency for retryable create/command
  operations where duplicate work would be harmful.
- Never expose stack traces, filesystem paths, provider payloads, secrets, or
  raw evidence.

New endpoints use the canonical error fields:

```json
{
  "error": {
    "code": "evidence_not_found",
    "message": "The requested evidence could not be found."
  },
  "request_id": "opaque-correlation-id"
}
```

Existing error envelopes remain supported until callers are inventoried and a
versioned compatibility migration is complete. Error codes are stable and
machine-readable; messages are safe for users; field validation errors identify
fields without echoing sensitive values.

Update API documentation and contract tests in the same change.

## 5. Logging, audit, and observability

Operational logs and audit records have different purposes:

- Operational logs diagnose runtime health and include timestamp, level,
  event name, request/correlation ID, component, safe entity IDs, duration,
  outcome, and exception class where relevant.
- Audit records are append-oriented security facts and include actor, action,
  target, authorization outcome, source context, request ID, timestamp, and
  result.

Use stable event names and structured fields. Never log passwords, tokens,
cookies, authorization headers, secret configuration, raw evidence, full AI
prompts containing case data, or unnecessary personal data. Redaction happens
before emission. Security-relevant events must fail safely if the audit sink is
unavailable and must surface an operational alert.

Every external dependency and background job defines latency, success,
failure, timeout, and queue-depth signals. Alerts must be actionable and linked
to a runbook.

## 6. Error and resilience standards

- Validate at the system boundary and enforce invariants in the domain.
- Translate infrastructure failures into application errors, then into stable
  transport responses at the outer boundary.
- Preserve causal context in server logs while returning safe client messages.
- Set explicit timeouts on network and analysis operations.
- Retry only transient, idempotent operations with bounded exponential backoff
  and jitter.
- Define degradation behavior for optional AI and intelligence providers.
- Background jobs are idempotent where practical and record state transitions,
  attempts, ownership, and terminal failure.
- Partial failures must not silently mark evidence or investigations complete.

## 7. Testing expectations

The test pyramid includes:

- Unit tests for domain rules, validators, policies, and pure transformations.
- Integration tests for repositories, storage, provider adapters, and
  application service composition.
- API/functional tests for happy paths, invalid input, authentication,
  authorization, CSRF, conflict, not-found, and safe error behavior.
- Security tests for permission coverage, upload limits and types, path
  handling, secret redaction, and evidence non-execution.
- Architecture tests for dependency and central-policy rules.
- UI tests for keyboard operation, focus, responsive behavior, and state
  handling when a user-facing surface changes.

Tests must be deterministic, isolated, order-independent, and free of live
provider dependencies. A defect fix includes a regression test. Changed code
must not reduce meaningful coverage; risk and behavior coverage matter more
than a vanity percentage. CI is the minimum gate, not a substitute for focused
local validation.

## 8. Documentation standards

- Public modules and non-obvious security decisions explain intent and
  invariants, not line-by-line mechanics.
- A user-visible or API behavior change updates the relevant guide and API
  documentation.
- Operational changes include configuration, deployment, monitoring, rollback,
  and runbook updates.
- Architectural decisions use ADRs with context, decision, alternatives,
  security impact, compatibility, and consequences.
- Diagrams identify trust boundaries and data classification when evidence or
  secrets cross components.
- Documentation examples use synthetic data only.

## 9. Git and review conventions

- Use short-lived branches and focused pull requests.
- Use Conventional Commit subjects: `type(scope): imperative summary`.
  Common types are `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`,
  `ci`, and `chore`.
- Do not mix broad formatting with functional changes.
- Do not commit secrets, production data, evidence, runtime databases, logs, or
  generated local state.
- Reviews assess correctness, compatibility, security, tests, operability,
  performance, accessibility, and maintainability.
- High-risk changes require a security reviewer and code owner: authentication,
  authorization, evidence lifecycle, upload parsing, cryptography, secrets,
  audit, plugins, AI data disclosure, deserialization, command execution, or a
  trust-boundary change.

## 10. Security review requirements

For security-sensitive changes, document:

1. Assets and data classification.
2. Actors, permissions, and least-privilege decision.
3. Entry points and trust boundaries.
4. Abuse cases and failure modes.
5. Validation, isolation, audit, and recovery controls.
6. Tests and residual risk.

Uploaded evidence follows validation, SHA-256 hashing, metadata extraction,
quarantine, security queue, future isolated analysis, intelligence correlation,
AI-assisted investigation, and reporting. The web process may store and
orchestrate evidence but never execute it. Hashes and chain-of-custody events
are immutable investigation facts.

## 11. Performance standards

- Establish a baseline before optimization and measure again afterward.
- Avoid N+1 queries, unbounded collections, duplicate requests, synchronous
  provider waits on critical rendering paths, and loading entire evidence
  objects when metadata is sufficient.
- Paginate tables and feeds; lazy-load genuinely heavy secondary surfaces.
- Cache only with explicit ownership, TTL, invalidation, tenant/user scope, and
  sensitivity rules.
- Stream long AI responses when the existing contract supports it, while
  preserving cancellation and a complete audit record.
- New endpoints and key UI flows define an expected latency and resource budget
  in their acceptance criteria. Regressions require evidence and approval.
- Performance work must preserve authorization and must not cache protected
  responses across principals.

## 12. Accessibility and responsive quality

User-facing work targets WCAG 2.2 AA. It must support keyboard-only use, visible
focus, semantic names, correct heading structure, screen-reader status
announcements, adequate contrast, reduced motion, zoom/reflow, and touch target
sizes. Color is never the only signal.

Desktop, laptop, tablet, and mobile layouts preserve the same authorized
capabilities through adaptive patterns. Tables, dialogs, charts, and forms need
purpose-built compact behavior; shrinking a desktop canvas is not acceptance.

## 13. Universal Definition of Done

A change is done only when all applicable statements are true:

- Acceptance criteria and threat-relevant failure cases are met.
- Existing routes, APIs, authentication, RBAC, and data remain compatible, or a
  reviewed migration and rollback plan exists.
- Architecture boundaries and shared-component rules are followed.
- Input is validated; authorization is explicit; evidence remains untrusted.
- Errors are safe and observable; security actions are auditable.
- Focused tests cover success, failure, and permission paths; the complete CI
  gate passes.
- Performance and dependency impact are measured or reasonably bounded.
- User-facing work is responsive and meets WCAG 2.2 AA expectations.
- API, developer, security, operations, and ADR documentation is current.
- No secrets, evidence, sensitive telemetry, or generated runtime state is
  committed.
- Reviewers can deploy, monitor, diagnose, and roll back the change.
- The author performs a final self-review and removes inconsistency, dead code,
  duplication, and avoidable complexity introduced by the change.

## 14. Incremental enforcement roadmap

1. Enforce lint, format, compilation, tests, and central permission coverage in
   CI.
2. Inventory legacy API error shapes and introduce a compatibility-tested
   canonical error adapter.
3. Move operational logging to structured output while retaining required
   deployment compatibility.
4. Add dependency-boundary tests and contract tests as feature modules are
   touched.
5. Add coverage reporting and ratchet thresholds from the measured baseline;
   do not impose an arbitrary number that incentivizes weak tests.
6. Add automated accessibility and dependency/security scanning with reviewed
   baselines and remediation ownership.
