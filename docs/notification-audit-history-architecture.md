# Notification, Audit, and Investigation History

## Event sources

The centralized history projection combines existing persisted sources without
creating synthetic events:

- user-owned notifications;
- case-scoped timeline events;
- actor-attributed database audit records;
- security alerts for administrators;
- authentication and access-control events for the affected user.

Non-administrators receive only events they performed or events linked to
investigations they own. Administrative access is required for platform-wide
security alerts and audit-integrity verification.

## Audit integrity

The structured audit file is append-only and flushed with `fsync`. New records
include:

- the hash of the preceding sealed record;
- a SHA-256 hash over the canonical event payload;
- request, actor, role, source address, path, result, and reason metadata.

Integrity verification is read-only and reports the number of sealed records.
Records written before hash chaining was introduced are counted as legacy
unsealed records rather than silently represented as verified.

Database audit rows have no update or delete API. Semantic events are recorded
for investigation lifecycle changes, evidence custody and analysis, timeline
observations, intelligence enrichment, report lifecycle operations, session
revocation, notification changes, and preference updates.

## Preferences

Notification preferences are stored in a user-specific settings namespace.
Updates accept only the existing allow-listed preference keys and generate an
actor-attributed audit event. Preferences affect delivery policy; they do not
erase historical audit or investigation events.

## Future controls

For multi-process production deployments, the hash writer should be moved to a
single durable audit sink or external append-only/WORM service so ordering and
retention guarantees extend across application workers and hosts.
