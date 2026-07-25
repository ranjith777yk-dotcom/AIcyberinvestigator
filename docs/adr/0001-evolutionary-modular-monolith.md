# ADR 0001: Evolve as a Modular Monolith

- Status: Accepted
- Date: 2026-07-25

## Context

CyberInvestigator already has working authentication, RBAC, investigation workflows, persistence, plugins, AI providers, and a versioned API. Replacing the application or prematurely distributing it would increase operational risk and threaten existing contracts.

The current pressure comes from large transport and frontend modules, not from a demonstrated need for independent services.

## Decision

CyberInvestigator will evolve as a modular monolith.

- The Flask application factory remains the composition root.
- Business capabilities are extracted behind application services and ports.
- API routes, authentication, database identifiers, and response shapes remain compatible during extraction.
- Modules communicate in-process through explicit DTOs and interfaces.
- Hostile evidence analysis becomes an isolated worker boundary when implemented; it does not require splitting the entire product.
- Durable queues, shared caches, or external services are introduced only for measured operational requirements.

## Consequences

Positive:

- Existing functionality remains deployable throughout the work.
- Transactions and local development remain simple.
- Boundaries can be tested before infrastructure is distributed.
- Future service extraction remains possible at explicit ports.

Trade-offs:

- Architectural discipline must be enforced within one repository.
- Large modules require incremental extraction.
- In-process background tasks remain limited until the durable analysis phase.

## Guardrails

- New domain code cannot depend on Flask, API, or presentation packages.
- New application code cannot depend on Flask, API, or presentation packages.
- Routes are delegated to feature handlers rather than expanded indefinitely in the central blueprint.
- Infrastructure implementations are selected only in the composition root.
- Cross-module database access must still enforce user/case scope.

