# Threat Hunting and Detection Engineering

CyberInvestigator's Threat Hunting Center is an additive investigation
capability. It is not a SIEM and does not claim continuous telemetry ingestion.

## Hunt lifecycle

Every hunt belongs to an accessible investigation and active organization. A
hunt records an investigator-authored name, hypothesis, scope, owner, and
lifecycle timestamps. Supported transitions are:

`draft → active → paused → active/completed`, with cancellation available from
non-terminal states.

Lifecycle transitions write investigation timeline events and tenant-stamped
audit events. Existing case access—owner, reviewer, case team, RBAC, and tenant
membership—remains the authorization boundary.

## IOC search and correlation

IOC search uses the established normalized indicator types and the actual
evidence inventory. Evidence SHA-256 values and indicators extracted from stored
analysis reports retain their evidence ID, evidence number, and filename
provenance.

Each valid search persists:

- the normalized type and value;
- actual matching evidence count;
- actual provider-finding count;
- provider execution status;
- one correlation record per matching evidence item.

Malformed searches are rejected and audited as failures. Provider enrichment is
optional. `unavailable` means no provider is configured; `unknown` or zero
findings never means benign.

## Detection rule repository

Rules are tenant-scoped, versioned, and administrator-managed through
`detection_rules.manage`. The repository accepts Sigma-compatible JSON with a
title, logsource, detection object, condition, and optional tags. ATT&CK coverage
is derived only from authored `attack.t####[.###]` tags.

Creating the same rule key creates a new immutable version. Status and enabled
state may be changed with an audited management operation.

The built-in evaluator intentionally supports only:

```json
{
  "detection": {
    "selection": {
      "indicator": [
        {"type": "url", "value": "https://example.test/path"}
      ]
    },
    "condition": "selection"
  }
}
```

This execution mode is reported as `indicator_match_v1`. Other Sigma semantics
remain stored and reusable but return `unsupported` rather than producing a
false detection. Alerts are created only when a normalized rule indicator
matches an actual stored evidence observation.

## Provenance

Detection alerts use `source=verified_evidence`. Provider findings remain
external assertions with provider attribution. AI hunt recommendations return
`provenance=ai_generated_suggestion` and `verified_finding=false`; they never
create detection alerts.

Verified detection alerts and hunt lifecycle data are included in generated
investigation reports. Detection matches create timeline events. Existing
threat-intelligence and evidence integrations remain the source of IOC and
provider data.

## API

- `GET /api/v1/threat-hunting`
- `POST /api/v1/threat-hunting/hunts`
- `PATCH /api/v1/threat-hunting/hunts/{hunt_id}`
- `POST /api/v1/threat-hunting/hunts/{hunt_id}/ioc-searches`
- `POST /api/v1/threat-hunting/hunts/{hunt_id}/ai-recommendations`
- `GET /api/v1/detection-rules`
- `POST /api/v1/detection-rules`
- `PATCH /api/v1/detection-rules/{rule_id}`
- `POST /api/v1/detection-rules/{rule_id}/evaluate`

The generated OpenAPI document remains authoritative for deployed endpoint and
permission metadata.
