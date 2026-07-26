# Changelog

All notable changes are recorded here. The project follows additive evolution
of the stable `/api/v1` contract; breaking HTTP changes require a new major API
path and migration guidance.

## Unreleased

### Added

- Implementation-derived, access-aware OpenAPI reference and developer portal.
- Preview Python, TypeScript, and Java SDK foundations.
- Prepared versioned webhook envelope and HMAC signature contract; delivery and
  subscription APIs remain unavailable.
- Governance, privacy, classification, retention-review, and export controls.
- Performance, capacity, cache, queue, and high-availability readiness workspace.
- Layered quality, browser, security, and release-evidence framework.

### Changed

- API v1 responses now identify the contract through `API-Version: v1`.
- Report export can enforce configured classification and purpose policy.
- Production concurrency and database pooling are environment-configurable.

### Compatibility

- Existing `/api/v1` routes remain the stable major contract.
- Existing default report-export behavior remains available until an
  administrator configures stricter governance policy.
