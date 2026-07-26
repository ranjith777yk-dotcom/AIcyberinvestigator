# ADR 0004: Additive organization boundary

## Status

Accepted

## Context

CyberInvestigator historically treated one deployment as one organization.
Replacing authentication or investigation workflows would create avoidable
compatibility and forensic-integrity risk.

## Decision

Add organizations and memberships beside the existing user/RBAC model. Use a
deterministic default organization for existing deployments and nullable tenant
foreign keys during migration. Backfill existing tenant-bearing records,
establish organization context before authorization, scope repositories and
aggregates to it, and stamp new records at the persistence boundary.

Membership constrains the data boundary; existing RBAC constrains capabilities.
An administrator is not implicitly a cross-tenant administrator.

## Consequences

Single-tenant clients remain compatible. Multi-tenant deployments gain logical
isolation without new authentication protocols. Every new tenant-bearing model
and query still requires a scoping review. Physical database isolation, billing,
outbound invitation delivery, and authoritative storage/AI metering remain
separate future integrations.
