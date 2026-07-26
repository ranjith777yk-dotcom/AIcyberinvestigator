# Team Collaboration and Case Assignment

CyberInvestigator collaboration is an additive, tenant-scoped extension of the
existing investigation workflow. Existing case owners, reviewers, evidence,
timelines, reports, and AI integrations remain unchanged.

## Access model

Every collaboration record carries both an organization and case identifier.
Requests must pass active organization membership and case access checks.
Existing administrators may access cases only in the active organization.

Case access is granted to:

- the existing case owner;
- the existing assigned reviewer;
- active case-team members;
- active-tenant administrators.

Case-team roles are `lead`, `investigator`, `reviewer`, and `observer`. Observers
are read-only. Case owners, team leads, and administrators manage membership.
The platform RBAC permissions `collaboration.read`, `collaboration.write`,
`collaboration.review`, and `collaboration.manage` remain configurable through
the existing role-permission system; case roles apply an additional,
record-level restriction.

## Collaboration records

- Tasks retain assignee, priority, state, due date, creator, and real completion
  time. A task can only be assigned to an active case participant.
- Discussion threads support replies through parent comment identifiers.
- Team comments are visible to case participants. Private notes are visible only
  to their author and do not generate mentions.
- `@username` mentions notify only active members of the same case team and
  organization.
- Review requests name a real active-organization reviewer. Only that reviewer
  or an administrator can record an approval, rejection, or changes-requested
  decision.

The collaboration dashboard reports stored assignments, comments, and mentions.
Empty investigations and single-participant investigations return empty
collections rather than sample activity or calculated completion claims.

## Audit and notifications

Team changes, task creation/state changes, discussions, comments, review
requests, and decisions write tenant-stamped audit events. Notification records
are tenant-stamped and recipient-scoped. Private comment bodies are not copied
into audit reasons or notifications.

No email, chat, or external notification delivery is claimed. The in-application
notification center is the implemented delivery channel.

## API

- `GET /api/v1/collaboration`
- `GET /api/v1/cases/{case_id}/collaboration`
- `POST /api/v1/cases/{case_id}/team`
- `POST /api/v1/cases/{case_id}/tasks`
- `PATCH /api/v1/collaboration/tasks/{task_id}`
- `POST /api/v1/cases/{case_id}/discussions`
- `POST /api/v1/collaboration/discussions/{thread_id}/comments`
- `POST /api/v1/cases/{case_id}/reviews`
- `PATCH /api/v1/collaboration/reviews/{review_id}`

The implementation-derived OpenAPI document remains authoritative for deployed
endpoint availability and permission metadata.
