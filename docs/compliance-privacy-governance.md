# Compliance, privacy, and governance

## Scope and truthfulness

CyberInvestigator provides governance controls and point-in-time evidence. It
does not declare that an organization complies with a law, regulation,
contract, or certification. Such conclusions require an authorized assessment
of configured policies, operating procedures, infrastructure, and evidence
outside this application.

The administrator-only workspace is `/admin/governance`; its API is
`GET /api/v1/admin/governance`. JSON and CSV point-in-time reports are available
from `/api/v1/admin/governance/report`. Missing or malformed policy records are
reported explicitly.

## Policy and classification

Governance policy is stored as a versioned, namespaced setting. It configures:

- whether explicit classification is required before report export;
- the default classification for unassigned investigations;
- retention-review intervals per classification;
- allowed report export formats per classification;
- whether an export purpose is required;
- whether disposition requires approval.

Supported classifications are public, internal, confidential, and restricted.
Assignments are recorded per investigation with actor, timestamp, and reason.
They do not alter forensic content or custody hashes.

Every policy and classification change requires the `governance.manage`
permission and creates an immutable application audit event. Governance setting
values are available only through administrator endpoints.

## Export governance

Existing report exports retain their route and formats. When a governance policy
is configured, the route additionally checks:

1. explicit classification when the policy requires it;
2. the format allow-list for the effective classification;
3. `X-Export-Reason` when export purpose is required.

Blocked and successful decisions are audited. The default policy preserves the
previous export behavior.

## Retention, legal hold, and disposition

Retention intervals produce review candidates based on actual investigation
dates. They never trigger automatic deletion. Each candidate identifies whether
an active legal hold blocks disposition.

The existing storage legal-hold contract remains authoritative and continues to
block evidence deletion. A disposition request creates an approval-review
record only. It does not delete database rows, evidence bytes, reports, backups,
or audit records.

The application does not claim physical secure erasure. Filesystems, snapshots,
replicas, backups, object stores, and copy-on-write layers require
provider-specific deletion and cryptographic-erasure evidence. Until such an
adapter exists, disposition records state `deletion_executed: false` and
`secure_erasure_verified: false`.

## Privacy requests

Administrators may record access, correction, restriction, and deletion-review
requests. `subject_reference` should be an internal opaque reference, not raw
identity documents or unnecessary personal information. Creating a request
does not automatically disclose, change, restrict, or delete investigation
records. Authorized review remains mandatory.

## Dashboard evidence

The workspace displays, in mobile priority order:

1. persisted critical/high governance, privacy, or storage alerts;
2. policy configuration and parsing state;
3. active persisted legal holds;
4. cases reaching configured retention review dates.

It also reports explicit and default classifications, privacy requests,
disposition reviews, storage integrity state, and relevant audit activity.
Metrics are counts from current persisted records; no compliance score,
fabricated violation, historical trend, or inferred certification is produced.
