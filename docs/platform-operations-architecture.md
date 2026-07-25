# Platform Operations Architecture

The Administration & Platform Operations Center is a privileged operational
surface. It remains separate from investigation workspaces and reuses the
existing authentication, RBAC, settings, audit, health, and monitoring
infrastructure.

## Operational contracts

- `GET /api/v1/admin/operations` returns observed readiness, persisted security
  alerts, background-job state, entity counts, maintenance state, audit
  integrity, and recent administrative activity.
- Capacity metrics that do not have a configured collector are returned as
  `unavailable` with a reason. The API never substitutes estimated CPU, memory,
  or storage values.
- `PATCH /api/v1/admin/alerts/<id>` supports the explicit `open`,
  `acknowledged`, and `resolved` lifecycle and records the actor in the audit
  trail.
- `GET|PATCH /api/v1/admin/maintenance` stores the maintenance state in the
  existing settings store and audits each transition.

All endpoints require the existing administrator role and endpoint permission
checks. Existing administration endpoints remain available for compatibility.

## Maintenance boundary

When maintenance mode is enabled, authenticated non-administrators receive a
`503` response before application handlers execute. Administrators retain
operations access so they can diagnose and recover the platform. Authentication,
static assets, and live/readiness probes remain reachable. Maintenance state
contains only an enabled flag, a user-facing message, and update attribution.

## Data integrity and failure behavior

The operations center uses persisted `SecurityAlert`, `AuditLog`, `Setting`, and
domain entity records plus current readiness checks and the configured job
registry. Unavailable collectors are visible as unavailable, and service
degradation is not converted into a healthy state. Administrative mutations
record actor, role, request source, affected object, and reason through the
shared audit path.

## Responsive information priority

Desktop uses a three-column operational grid. Tablet reduces to two columns.
Mobile intentionally orders Critical Alerts, Platform Health, Active Issues,
Resource Usage, Administrative Activity, then Maintenance controls. No
capability is removed at smaller breakpoints, and controls retain touch-sized
targets and semantic labels.

## Future extension points

External telemetry can be added behind collectors for CPU, memory, storage,
queue depth, and latency without changing the response shape. Alert provider
adapters should normalize into persisted security alerts. Multi-node
maintenance coordination will require a shared configuration store and should
preserve the same audited API contract.
