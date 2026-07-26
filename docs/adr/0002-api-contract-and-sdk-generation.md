# ADR 0002: Route-derived API contract and SDK previews

- Status: Accepted
- Date: 2026-07-26

## Context

CyberInvestigator already exposes a large stable `/api/v1` surface and
centralizes endpoint permissions, but its earlier OpenAPI output did not
normalize paths or describe authorization. Maintaining a second handwritten
endpoint inventory would drift.

## Decision

Generate OpenAPI from the running Flask route map and centralized permission
registry. Normalize Flask parameters, provide stable operation IDs, schemas,
security schemes, response envelopes, visibility, and required-permission
extensions. Filter administrative operations unless the requesting principal is
an administrator.

SDKs begin as explicitly labeled previews whose authoritative contract is the
generated specification. Publication and complete generated operation coverage
are deferred until contract parity, packaging, and compatibility automation are
implemented.

## Consequences

Route/spec parity is testable and internal APIs are not disclosed to ordinary
users. Operation request/response schemas remain partially generic until
endpoint-specific schema metadata is added. Breaking changes require a new
major path rather than mutation of `/api/v1`.
