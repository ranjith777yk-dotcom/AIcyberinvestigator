# CyberInvestigator API v1

## Contract and compatibility

`/api/v1` is the stable major REST contract. Additive endpoints and fields may
be introduced within v1. Removing or changing established behavior requires a
new major API path, migration guidance, and deprecation notice.

Every v1 response includes:

```http
API-Version: v1
```

The authenticated OpenAPI 3.0 document is:

```text
GET /api/v1/openapi.json
```

It is generated from registered routes and centralized permission policy.
Administrators see administrative operations; ordinary authenticated users
receive the user-visible contract. The developer portal is `/developers`.

## Authentication, authorization, and CSRF

The current application uses a secure server-managed session cookie.
Permissions are resolved by server-side RBAC; client-supplied role headers are
accepted only by the isolated testing profile.

State-changing browser requests require `X-CSRF-Token` when CSRF protection is
enabled. Possession of a CSRF token does not grant permission. Administrative
endpoints require their documented `x-required-permissions` values.

Do not place credentials in URLs, source code, SDK configuration committed to
version control, logs, webhook payloads, or report content.

## Errors, pagination, and tracing

Most validation errors use:

```json
{"error": "Safe explanation"}
```

Unexpected errors use a safe error identifier and do not disclose stack traces.
Callers must handle at least `400`, `401`, `403`, `404`, `409`, `429`, and
`500`. Collection endpoints that support pagination return their current
pagination envelope; inspect the operation and response rather than assuming
all collections use identical query parameters.

Requests support `X-Request-ID` and W3C `traceparent`. Responses include
`traceparent` and `Server-Timing`.

## Operational endpoints

- `GET /api/v1/health/live` is a process liveness probe.
- `GET /api/v1/health/ready` checks required runtime readiness.
- `GET /api/v1/monitoring/metrics` requires operational monitoring permission.

Readiness describes the current process and configured dependencies. It is not
a historical availability report.

## Exports and governance

Evidence, timeline, report, and governance exports are audited. Report export
may be restricted by investigation classification, allowed format, and
`X-Export-Reason`. A `403` or `409` governance decision must not be bypassed by
an SDK.

## SDK and webhook status

Preview client foundations exist under `sdk/python`, `sdk/typescript`, and
`sdk/java`. They are not published packages and do not claim complete operation
coverage. The generated OpenAPI contract remains authoritative.

A webhook event envelope and signing format are prepared. Subscription APIs,
delivery workers, retries, and delivery history are unavailable.

## Discovering operations

Use the developer portal or OpenAPI paths rather than a manually maintained
endpoint list. This prevents documentation from claiming endpoints that the
running application does not register.
