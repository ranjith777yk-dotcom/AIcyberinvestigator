## Outcome

<!-- What user or engineering outcome does this change deliver? -->

## Scope and compatibility

<!-- Routes, APIs, authentication, RBAC, data, configuration, and rollback impact. -->

- [ ] Existing routes and supported API behavior remain compatible, or the migration is documented.
- [ ] Authentication and authorization behavior has been preserved or explicitly security-reviewed.
- [ ] No database change, or a backward-compatible migration and rollback plan is included.

## Verification

<!-- Tests run and relevant manual scenarios. -->

- [ ] Ruff lint and format checks pass.
- [ ] The test suite passes and new behavior has focused tests.
- [ ] Error, loading, empty, and permission-denied paths were considered.

## Security and evidence

- [ ] Untrusted input is validated at the boundary.
- [ ] Evidence is never executed by the web process.
- [ ] Logs, errors, and telemetry contain no secrets or raw evidence.
- [ ] Security-relevant actions are authorized and auditable.
- [ ] Threat model or security documentation is updated when a trust boundary changes.

## Operations and quality

- [ ] Logging, metrics, timeouts, and failure behavior are appropriate.
- [ ] Performance impact and query/API call growth were considered.
- [ ] User-facing changes meet responsive and WCAG 2.2 AA expectations.
- [ ] Documentation and ADRs are updated where required.
- [ ] A rollback path is understood.
