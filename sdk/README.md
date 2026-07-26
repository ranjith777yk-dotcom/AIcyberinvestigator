# CyberInvestigator SDK previews

These clients are preview foundations, not published packages. Their supported
source of truth is the authenticated `GET /api/v1/openapi.json` contract.

Each preview provides:

- base URL and session-token/cookie configuration;
- generic JSON request handling;
- API-version response validation;
- health and OpenAPI convenience operations.

They do not claim generated coverage for every endpoint, automatic retries,
webhook delivery, package-registry publication, or semantic-version stability
beyond the existing v1 HTTP contract.

Run contract parity tests before publishing any SDK. Generated clients must not
embed credentials, log session cookies, or silently retry non-idempotent
requests.
