# Threat Intelligence Correlation

## Trust boundary

Extracted indicators are observations, not verdicts. The application normalizes
them before correlation and retains the originating evidence identifiers.
`unknown` means that no configured provider returned a finding; it never means
`benign`.

Provider adapters implement `ThreatIntelligenceProvider`. They own credential
lookup, transport security, timeouts, response validation, and provider-specific
rate limits. Adapters must return `IntelligenceFinding` records and must not put
API credentials or complete raw provider responses into logs.

## Correlation contract

Each provider assertion keeps these dimensions separate:

- reputation: unknown, benign, suspicious, or malicious;
- provider-supplied confidence, when present;
- observation and retrieval timestamps;
- provider and reference;
- supported ATT&CK technique identifiers;
- originating investigation evidence.

ATT&CK mappings are returned only when a provider finding supplies the
technique. The correlation engine does not infer campaigns, actors, malware
families, or techniques from reputation.

## API and access control

- `GET /api/v1/threat-intelligence?case_id=...` returns the normalized,
  ownership-scoped indicator inventory without contacting providers.
- `POST /api/v1/threat-intelligence/enrich` performs explicit enrichment for an
  accessible investigation and records a semantic audit event.

Both endpoints are protected by dedicated RBAC permissions. Enrichment audit
records contain counts and provider totals, not indicator values or secrets.

## Extension model

Configured adapters are composed through
`cyberinvestigator_threat_intelligence_providers`. The response includes a
graph-ready node/edge envelope so a future visualization can be introduced
without changing provider contracts or weakening investigation ownership.
