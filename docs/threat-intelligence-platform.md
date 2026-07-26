# Threat Intelligence Platform and Knowledge Graph

CyberInvestigator's Threat Intelligence Center extends the existing provider
normalization and evidence-correlation capabilities. It does not replace a
dedicated TIP or claim support for unconfigured intelligence feeds.

## Intelligence provenance

The platform stores three distinct record types:

- normalized IOC lifecycle records;
- sourced intelligence objects;
- provenance-bearing relationships.

Evidence-derived IOC observations are marked through verified `observed_in`
relationships to preserved evidence. Provider reputation, summaries, ATT&CK
techniques, references, and confidence remain provider assertions in separate
`provider_finding` objects. Provider assertions are not automatically marked as
verified intelligence.

Analyst imports require an object type, source-specific external ID, source, and
reference. Threat actor, campaign, malware, CVE, and ATT&CK views remain empty
until a real provider response or audited import supplies those records.

## IOC lifecycle

Supported lifecycle states are:

- `new`;
- `active`;
- `monitoring`;
- `expired`;
- `revoked`;
- `false_positive`.

IOC values use the existing provider-neutral normalization contract. Searches
correlate against evidence visible through the current investigation access
boundary. Search attempts, including normalization failures, are audited.
Optional provider enrichment reports unavailable when no providers are
configured; zero findings never means benign.

## Knowledge graph

Stored graph edges include their relationship type, provenance, verification
state, optional provider confidence, and reference. The graph also derives
read-only links from existing application records:

- indicator to evidence;
- evidence to investigation;
- investigation to reports and timeline events;
- indicator to verified detection alerts;
- indicator to provider findings.

Derived links do not assert threat attribution. Evidence relationships outside a
user's accessible investigations are excluded. Tenant isolation applies to every
stored node and relationship.

## AI summaries

AI receives only the stored record types, lifecycle states, source labels, and
provider attribution needed for summarization. Responses return
`provenance=ai_generated_observation` and `verified_intelligence=false`. AI does
not create actors, campaigns, malware, CVEs, graph edges, or confidence values.

## Provider and sharing security

Provider adapters continue to own credentials and transport. Credential-like
fields (`password`, `secret`, `token`, `api_key`, and `credential`) are removed
recursively before provider attributes are persisted or returned.

The `IntelligenceSharingAdapter` contract prepares for authenticated STIX/TAXII
integration. The default adapter truthfully reports unavailable with import and
export disabled. No standards-sharing capability is claimed without a configured
adapter.

Imports, relationship creation, lifecycle edits, searches, enrichments, and AI
summary requests are tenant-stamped in the audit log.

## API

- `GET /api/v1/intelligence-center`
- `POST /api/v1/intelligence-center/iocs/search`
- `PATCH /api/v1/intelligence-center/iocs/{indicator_id}`
- `POST /api/v1/intelligence-center/objects`
- `POST /api/v1/intelligence-center/relationships`
- `POST /api/v1/intelligence-center/ai-summary`
- `POST /api/v1/threat-intelligence/enrich`

The implementation-generated OpenAPI document is authoritative for deployed
permissions and endpoint availability.
