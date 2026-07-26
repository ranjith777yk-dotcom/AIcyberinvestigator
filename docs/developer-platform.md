# Developer platform guide

## Audiences

- Investigators use product guides for cases, evidence, timelines, AI review,
  and reports.
- Administrators use identity, governance, storage, deployment, quality, and
  performance architecture guides.
- API integrators use the authenticated developer portal and OpenAPI contract.
- Plugin authors use the plugin connector and Java plugin documentation.
- Contributors use the developer guide, engineering standards, ADRs, tests, and
  changelog.

## Portal architecture

`/developers` is authenticated and responsive. On mobile its information order
is Documentation Search, API Reference, Guides, then Release Notes. Search is
performed locally over the operations visible in the caller's generated
OpenAPI document and the server-provided guide catalog.

The portal does not execute arbitrary API calls. This avoids turning
documentation into a privileged request proxy and prevents accidental mutations
from an interactive console. It presents methods, paths, operation IDs,
permissions, parameters, response codes, and CSRF requirements, while the
downloadable OpenAPI document supports approved external tooling.

## Maintaining API documentation

1. Preserve or intentionally version route paths.
2. Add the endpoint to centralized permissions.
3. Define request/response dataclasses when the contract is stable.
4. Add integration and route/spec parity tests.
5. Update guides, changelog, and an ADR for consequential decisions.
6. Regenerate or verify SDKs against an authenticated appropriate-visibility
   OpenAPI document.

Never copy production-only administrative specifications into public
documentation artifacts.

## SDK lifecycle

The current SDK directories are preview source foundations. Before publication:

- select package names and ownership;
- generate typed models and operations from OpenAPI;
- add session and CSRF integration tests;
- add pagination, streaming, upload, download, timeout, and cancellation tests;
- define retry policy for idempotent operations only;
- add semantic versioning and supported-runtime matrices;
- publish signed provenance and release notes.

The existing Java plugin framework is separate from the Java REST SDK preview.

## Webhook lifecycle

The prepared envelope and signature format are not a delivery system. A
production implementation requires a transactional outbox, allow-listed HTTPS
destinations, encrypted rotating secrets, delivery workers, exponential
backoff, dead letters, idempotency identifiers, timestamp/replay validation,
redacted audit events, and administrator RBAC.
