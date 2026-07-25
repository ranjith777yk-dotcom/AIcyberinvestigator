# CyberInvestigator Security Architecture

## Security Objective

CyberInvestigator protects identities, case-scoped investigation data, evidence custody, analysis results, AI context, reports, and operational telemetry. The security model assumes every request, uploaded file, external provider, plugin, and generated result may be hostile.

The platform follows Zero Trust principles: verify explicitly, authorize every protected operation, minimize privileges and data exposure, and retain evidence of security-relevant actions.

## Trust Zones

```text
Untrusted client
    |
    | HTTPS + request limits + CSRF
    v
Web/API boundary
    |
    | authenticated principal + permission + case scope
    v
Application use cases
    |                         |
    | metadata transaction    | opaque evidence identity
    v                         v
Database trust zone       Quarantine storage
                                  |
                                  | future durable security queue
                                  v
                         Isolated analysis worker
                                  |
                                  | normalized findings only
                                  v
                       Correlation and AI boundary
                                  |
                                  v
                         Versioned reports
```

The web process must never execute, import, mount as executable, or directly serve evidence bytes.

## Identity and Authorization

- Production requires authentication.
- Password verification, lockout, OAuth, session creation, renewal, and logout remain centralized in the security layer.
- Successful sessions have a server-side hashed token record.
- Production cookies are HTTP-only, secure, and use an explicit SameSite policy.
- Production bootstrap secrets must be supplied explicitly.
- Authorization combines an active session, named endpoint permission, and database-level ownership/case scope.
- Administrative bypasses remain explicit and tested.
- Template RBAC improves usability but is never treated as an enforcement boundary.

New endpoints must be classified as public, authenticated, case-scoped, privileged, or administrative; added to the endpoint-permission map unless explicitly public; and scope queries before serialization.

## Secure Evidence Lifecycle

### Implemented flow

1. Validate evidence identifiers, filenames, media-type claims, provenance text, and request size.
2. Stream bytes through the custody adapter.
3. Enforce the evidence-specific size limit inside the adapter.
4. Calculate SHA-256 while writing.
5. Derive basic MIME metadata without executing content.
6. Atomically preserve the completed file in quarantine.
7. Apply restrictive file permissions.
8. Store immutable custody metadata with pending analysis state.
9. Resolve reads through a canonical approved-root locator.
10. Retain read compatibility for legacy incoming files while all new writes use quarantine.

Storage paths are opaque server-generated identifiers. Original filenames are metadata only.

### Required future flow

```text
quarantine
  -> durable security queue
  -> ephemeral isolated worker
  -> type validation / malware scanning / bounded extraction
  -> normalized signed result
  -> threat-intelligence correlation
  -> policy-minimized AI context
  -> traceable report
```

The `AnalysisRunner` application port defines this future boundary. The current in-process analyzer and job dispatcher are not isolation or durability controls.

Future workers require a non-root identity, read-only root filesystem, non-executable evidence mount, disabled network by default, no application credentials, strict resource limits, signed analyzer images, and schema-validated results containing analyzer provenance and the source SHA-256.

## AI Security Boundary

- Features use provider-neutral request/response contracts.
- Provider credentials never enter prompts or client responses.
- Raw evidence is not sent to AI providers by default.
- Context is minimized to authorized derived findings.
- Prompts and model output remain untrusted data.
- AI recommendations cannot mutate evidence, access, or case state without a separately authorized action.
- Provider calls use timeouts, bounded retries, safe errors, and availability fallback.

## API and Secret Protection

- API v1 remains the compatibility boundary.
- Mutating browser requests require CSRF validation.
- Request size is bounded globally and again at evidence storage.
- Rate limits key on source and resolved identity.
- Errors expose safe messages and request identifiers.
- CSP and browser headers restrict framing, MIME sniffing, referrers, capabilities, resources, and form targets.
- Secrets inventory exposes configuration presence only.
- Secrets come from runtime injection or a secret manager and never enter source, browser storage, logs, exception responses, or AI prompts.
- For multi-process production, rate limiting must move to a shared atomic store behind the existing boundary.

## Audit Standard

Security audit files use one JSON object per line through `StructuredAuditWriter`. Each record includes timestamp, stable event name, request identifier, method, path, status, actor, role, source address, user agent, and a sanitized reason.

Audit text is bounded and stripped of control characters. Writes are serialized and flushed. Database audit records remain available for product workflows.

Event names use `domain.action`, including `auth.login`, `auth.logout`, `csrf.blocked`, `rbac.blocked`, `rate_limit.blocked`, `evidence.registered`, `evidence.analysis.completed`, and `report.generated`.

Audit records must not contain evidence bytes, passwords, tokens, secret values, full AI prompts, or sensitive report content. Production should ship them to access-separated append-only storage.

## Monitoring Readiness

Existing health, readiness, metrics, security-center, alert, and audit surfaces form the base. Future telemetry should include:

- authentication failure, lockout, authorization rejection, and CSRF rejection rates;
- upload size, quarantine failure, and hash verification counts;
- security queue depth and age;
- analyzer duration, timeout, resource-limit, and failure counts;
- provider availability, latency, fallback, and error rates;
- report and plugin execution outcomes;
- audit-pipeline delivery failures.

Metrics must not use usernames, case titles, filenames, hashes, or other sensitive/high-cardinality labels.

## Responsive Security UX

Security controls are identical on desktop, laptop, tablet, and mobile. Smaller layouts cannot hide required warnings, permission context, destructive-action consequences, session errors, or evidence state. Critical controls retain explicit labels, non-color cues, keyboard access, and touch-safe targets.

## Production Baseline

Production requires HTTPS, secure cookies, HSTS, explicit core secrets and trusted hosts, transactional persistence, separate quarantine/report volumes, restricted filesystem ownership, tested backups, centralized logs/secrets, dependency scanning, and controlled deployment identities.

## Incremental Roadmap

1. **Implemented:** quarantine-by-default storage, canonical locator, storage limits, structured audit writer, permission/case isolation, provider and job ports.
2. **Durable control plane:** shared rate limiter, durable queue, idempotent jobs, retry/dead-letter policy.
3. **Isolated analysis plane:** sandboxed workers, malware scanning, content validation, bounded extraction, signed results.
4. **Operational maturity:** SIEM export, alert rules, tracing, SLOs, retention, key rotation, backup verification.
5. **Assurance:** module threat models, SAST/SCA/secret scanning, controlled DAST, SBOMs, signed releases, incident exercises.
