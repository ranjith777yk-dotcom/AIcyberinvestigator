# ADR 0007: Evidence-backed detection evaluation

## Status

Accepted

## Decision

Build hunts on existing tenant-scoped investigations and normalized evidence
indicators. Store versioned Sigma-compatible rule definitions, but execute only
the explicitly supported `indicator_match_v1` subset. Reject unsupported
semantics without generating alerts.

Persist evidence correlations, provider status, and verified alerts separately.
Treat ATT&CK tags as authored rule coverage, provider findings as external
assertions, and AI recommendations as non-verified suggestions.

## Consequences

The platform gains reusable hunt and rule workflows without pretending to ingest
live SIEM telemetry or fully implement Sigma backends. Future detection adapters
can add supported execution semantics while preserving the rule repository,
tenant boundary, provenance, and audit model.
