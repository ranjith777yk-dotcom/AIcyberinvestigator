# ADR 0006: Quarantined, non-executing evidence analysis

## Status

Accepted

## Decision

Retain the existing quarantine storage and bounded forensic analyzer. Add
durable analysis-run, finding, artifact-provenance, and append-only custody
records. Re-verify the complete SHA-256 before producing findings. Treat static
observations as verified only after integrity succeeds and label AI output as
interpretation.

Define a provider-neutral sandbox adapter but configure an unavailable adapter
by default. Do not execute evidence or submit it to external services from the
web application.

## Consequences

Existing evidence APIs and storage paths remain compatible. The platform gains
queryable forensic provenance and future adapter extensibility. Dynamic behavior
and malware verdicts remain unavailable until a separately isolated, explicitly
configured provider is implemented and validated.
