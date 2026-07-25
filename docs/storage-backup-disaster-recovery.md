# Storage, backup, and disaster recovery architecture

## Current provider

CyberInvestigator composes evidence ingestion through the existing
`EvidenceStorage` port. The active adapter remains the local quarantine
filesystem so existing storage identifiers, analysis workflows, ownership, and
APIs are unchanged. The administration workspace reports measured capacity,
managed-root availability, file counts, and byte counts from that provider.

Provider capabilities are explicit. Local storage supports atomic writes,
restricted file permissions, and SHA-256 hashing. It does not claim object
versioning, object lock, or server-side encryption. Application-level evidence
encryption is not enabled because silently encrypting existing custody files
would break forensic analysis and compatibility. Production deployments should
place the instance, quarantine, and backup roots on encrypted volumes. TLS is a
deployment boundary and is reported as deployment-managed rather than inferred.

## Evidence integrity and legal holds

- Evidence is hashed while streaming into quarantine and is never executed by
  the web process.
- Administrators can run an explicit custody verification that recomputes file
  size and SHA-256 for every persisted evidence record.
- Verification results, failures, actors, and timestamps are audited.
- Investigation legal holds are stored as namespaced platform policy and block
  evidence soft deletion while active.
- Retention policy never deletes evidence automatically. Automated disposition
  requires a future reviewed custody workflow.

## Verified backups

`POST /api/v1/admin/storage/backups` creates a local recovery point:

1. A SQLite online backup API snapshot is written to a private partial folder.
2. Quarantined evidence and reports are copied without following symbolic links.
3. Every file receives a SHA-256 and size entry in `manifest.json`.
4. The full manifest is verified.
5. The partial folder is atomically published only after verification succeeds.

Only one backup can run per application process. Backup activity and failures
are written to the audit trail and notification center. The PowerShell backup
script emits the same manifest shape; for a transactionally consistent live
SQLite snapshot, the authenticated application workflow is preferred.

## Restore workflow

The web application never overwrites its active database or custody store.
Restore planning verifies the selected manifest and records a
`ready_for_offline_restore` plan. It does not claim a completed restore.

The offline recovery script refuses backups with missing or mismatched manifest
entries, supports verification-only execution, and reminds operators to stop
workers and perform post-restore database, evidence, and audit checks.

Recovery point and recovery time objectives remain `null` until operators
define and validate them. No availability or recovery result is fabricated.

## Access and responsive presentation

Storage endpoints require both the existing administrator role guard and the
server-side `storage.manage` permission. Policy, hold, backup, verification, and
restore-plan actions are audited.

On mobile the workspace order is Storage Health, Backup Status, Capacity,
Alerts, and Recent Restores, followed by integrity, policy, encryption posture,
and legal holds.
