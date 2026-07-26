# Multi-Tenant SaaS and Organization Management

CyberInvestigator supports an additive organization boundary while retaining the
existing single-tenant operating model.

## Compatibility model

`MULTI_TENANT_ENABLED` defaults to `false`. Startup migrations create a stable
`default` organization, enroll existing users, and backfill existing cases, AI
conversations, and audit events into that organization. Existing API clients
continue to operate without tenant headers or URL changes.

When multi-tenant mode is enabled, an authenticated database user must have an
active membership in the selected organization. Browser sessions retain that
selection. `X-CI-Organization` is accepted only in the testing environment.

## Isolation and authorization

Each request establishes an organization context before maintenance, rate-limit,
CSRF, and endpoint authorization checks. Missing or inactive memberships are
rejected. Case repositories and case-derived evidence, timeline, reporting, and
AI-conversation queries use that context. Administrators retain their RBAC
permissions, but those permissions do not bypass the active organization.

Organization mutations require `organizations.manage`. Platform roles answer
what an identity may do; organization membership answers where it may do it.
Persistence hooks stamp organization identifiers on new cases, AI conversations,
and audit events. Organization changes and quota blocks are audited.

## Organization data

The platform persists organizations, memberships, hashed expiring invitations,
allow-listed settings, and quotas. The workspace derives user, investigation,
and AI-conversation usage from the database. Empty organizations return zero
counts and empty collections.

Subscription status remains null until a real billing integration supplies it.
Invitation delivery reports unavailable because no transport is configured. The
currently enforced quotas are investigations and members/pending invitations.
Storage and AI-request quota records are preparatory until authoritative
metering exists.

## Operations

1. Back up the database before enabling the feature.
2. Deploy the additive migration with `MULTI_TENANT_ENABLED=false`.
3. Verify the default organization, memberships, and backfilled records.
4. Create organizations and memberships through controlled administration.
5. Enable multi-tenant mode in staging and execute isolation tests.
6. Review audit output and rollback plans before production enablement.

Tests must not reuse production databases, storage prefixes, credentials, or
invitation transports. Physical database-per-tenant and encryption-key-per-tenant
isolation are not implied by this logical boundary.

## API surface

- `GET /api/v1/organizations`
- `POST /api/v1/organizations`
- `POST /api/v1/organizations/{organization_id}/switch`
- `GET /api/v1/organizations/current`
- `PUT /api/v1/organizations/current/settings`
- `POST /api/v1/organizations/current/invitations`
- `PUT /api/v1/organizations/current/quotas/{resource}`

The generated OpenAPI document is the source of truth for request and response
details.
