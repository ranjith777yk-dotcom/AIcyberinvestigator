# ADR 0003: Prepare webhook contracts without claiming delivery

- Status: Accepted
- Date: 2026-07-26

## Context

Reliable webhooks require durable subscriptions, a transactional outbox,
workers, retry/backoff, dead-letter handling, replay protection, secret
rotation, delivery audit, and destination controls. None is currently deployed.

## Decision

Define only a versioned event envelope and HMAC-SHA256 signing/verification
format. Do not expose subscription endpoints or emit events until a durable
outbox and protected delivery adapter exist.

## Consequences

Future work has a testable serialization and signing boundary without
misrepresenting delivery capability. Webhook payloads must contain identifiers
and approved derived fields, never credentials or raw evidence bytes.
