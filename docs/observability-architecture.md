# Observability architecture

CyberInvestigator exposes an authenticated operations workspace at
`GET /api/v1/admin/observability`. Access requires the server-enforced
`security.monitor` permission and the endpoint currently retains the existing
administrator role guard.

## Signal model

- **Metrics:** every Flask request contributes its measured duration, response
  status, route, and method to a bounded, thread-safe process registry.
- **Traces:** inbound W3C `traceparent` identifiers are correlated with a new
  server span. Responses return `traceparent` and measured `Server-Timing`.
- **Logs:** application log events are written as rotating, one-event-per-line
  JSON. Common credentials are redacted before persistence and again before
  API presentation.
- **Health:** readiness reports database, plugin-loader, and configured AI
  provider state. Audit-chain verification is surfaced separately.
- **Events and alerts:** the workspace reads persisted audit records and
  security alerts; it does not synthesize operational incidents.

## Truthfulness and retention

Request history is process-local and bounded by `OBSERVABILITY_MAX_TRACES`
(default `5000`). It resets on process restart and is not presented as
long-term availability data. Minute history is calculated only from retained
request samples. External infrastructure metrics and distributed trace
exporters are explicitly reported as unavailable until they are configured.

This boundary permits a later OpenTelemetry/Prometheus adapter without changing
the current routes or response semantics.

## Security boundaries

- Query strings and request bodies are not retained in traces.
- Route templates are retained instead of concrete dynamic URLs; unmatched
  requests share one bounded label to prevent high-cardinality metric growth.
- Inbound request IDs and W3C trace identifiers are validated before reuse.
- Raw log file paths are not returned by the observability API.
- Secret-like authorization, token, password, API-key, and credential URL
  patterns are redacted.
- Monitoring requests participate in the existing administrative audit flow.
- Alert lifecycle mutations continue through the existing audited endpoint.
- Application and package-level loggers share the same structured, redacted
  rotating handler, and API log tails are read with bounded memory.

## Responsive presentation

The monitoring tab uses an adaptive grid. On mobile its semantic and visual
priority is Critical Alerts, Platform Health, Service Status, Recent Events,
then request telemetry, traces, logs, source availability, and background jobs.
