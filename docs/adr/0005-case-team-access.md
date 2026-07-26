# ADR 0005: Case-team access extends case ownership

## Status

Accepted

## Decision

Retain existing case owner and reviewer fields and add tenant-stamped case-team
membership. Extend the existing centralized case-access function so all
case-derived evidence, timeline, report, and AI paths inherit team access.
Apply platform RBAC, tenant membership, case access, and case-team role checks
cumulatively.

Private discussion notes are author-only. Collaboration mutations emit audit
events, while notification payloads contain routing context rather than private
content.

## Consequences

Existing investigation APIs remain compatible and do not require team records.
Single-participant cases continue to work. New case-derived endpoints must use
the centralized case-access boundary, and new collaboration tables must always
carry organization and case identifiers.
