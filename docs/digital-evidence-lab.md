# Digital Evidence Laboratory

The Digital Evidence Lab extends CyberInvestigator's existing evidence custody
workflow. It does not execute uploaded files and is not a malware sandbox.

## Intake and custody

Evidence intake retains the established case-access and RBAC checks. Files are
size-bounded, written to the configured quarantine root, and SHA-256 hashed
during storage. The original filename is metadata only and does not determine
the custody path.

Each intake, analysis start, completion, failure, and soft deletion appends a
tenant- and case-scoped custody event containing the persisted evidence digest.
Custody events have no update/delete API, and ORM update/delete operations are
rejected. Soft deletion removes evidence from active inventory but retains the
custody bytes.

## Static analysis

The built-in analyzer:

- streams the complete custody object to verify its persisted SHA-256;
- reads at most the configured bounded analysis window;
- identifies file signatures and metadata;
- computes entropy and extracts bounded printable strings;
- inspects supported archive children in memory with depth, child-count, and
  decompression limits;
- records observed indicators and extracted-child hashes.

Uploaded content is never imported, launched, or passed to a shell. Extracted
children are not published as executable files. A failed integrity check creates
no verified findings or artifacts.

Each execution creates a durable analysis run with analyzer/version, module
manifest, expected digest, integrity result, status, and timestamps. Normalized
findings use `source=static_analysis` and `verified_observation=true`. Extracted
artifact records retain their analysis-run provenance, source location, detected
signature, and content hash where bytes were available.

## AI, intelligence, timelines, and reports

Static observations remain the source of truth. Optional AI output is stored
under `ai_explanation` with `provenance=ai_generated_interpretation`; it is not
written as a verified forensic finding.

Existing threat-intelligence correlation consumes observed hashes and indicators
from evidence analysis. Analysis completion remains integrated with the
investigation timeline. Existing report generation consumes the stored analysis
report and therefore retains evidence provenance, recovered artifacts, and the
AI/static distinction.

## Sandbox adapter boundary

`SandboxAdapter` defines a future external isolated-provider boundary. The
default adapter is deliberately unavailable and reports:

- `configured=false`;
- `status=unavailable`;
- `submission_enabled=false`.

The web application exposes no dynamic execution or default submission path. A
future adapter must transfer evidence to a separately isolated trust zone,
authenticate provider responses, apply tenant policy, and persist only actual
provider observations.

## API

- `GET /api/v1/evidence-lab`
- `GET /api/v1/evidence/{evidence_id}/lab`
- `POST /api/v1/evidence`
- `POST /api/v1/evidence/{evidence_id}/analysis-jobs`
- `GET /api/v1/evidence/analysis-jobs/{job_id}`

Legacy evidence endpoints remain compatible. The implementation-generated
OpenAPI document is authoritative for deployed permissions and schemas.
