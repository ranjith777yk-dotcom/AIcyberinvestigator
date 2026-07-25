# Identity and Access Architecture

CyberInvestigator separates authentication, authorization, and investigation
ownership while retaining the existing routes and persistence model.

## Authentication

Passwords are verified using the existing adaptive password hashing path.
Unknown identities are checked against a process-local dummy hash so the
negative path does not skip password verification work. Attempts against locked
accounts are retained as blocked authentication audit events.
Successful authentication creates a random server-side session token and stores
only its SHA-256 digest. Opening a replacement session invalidates the prior
token and clears client session state before new identity state is established.
Account suspension, disabling, and administrative password rotation revoke all
active sessions.

MFA, SSO, and directory integrations are explicit extension points. The identity
API reports them as `not_configured`; it does not imply that an integration is
available.

## Authorization

Roles and permissions are persisted independently from authentication state.
Endpoint permissions are enforced in the server request boundary. Built-in
`admin` and `user` roles remain compatible, while custom roles retain their
persisted names and grants instead of being collapsed to a generic user role.

Custom roles may satisfy permission-protected administration endpoints without
receiving implicit investigation-wide ownership access. The system
administrator role must retain `admin.access` and `users.manage`.

## User lifecycle

Administrators can create accounts, assign any persisted role, activate,
suspend, disable, unlock, and rotate credentials through existing user routes.
The final active administrator cannot be disabled or reassigned, and an
administrator cannot disable or reassign their own account.

Every user, role, grant, and managed-session mutation records the acting
identity, role, request source, affected object, and reason in the shared audit
trail.

Unassigned custom roles can be retired through an audited operation. System
roles and roles with assigned users cannot be deleted; users must be reassigned
first.

## Session operations

Users retain ownership-scoped session visibility and revocation. The privileged
identity workspace adds cross-user session visibility and revocation guarded by
`users.manage`. Raw session tokens are never returned by APIs or rendered in the
interface.

## Investigation ownership

IAM grants do not rewrite investigation ownership. Existing case ownership
checks remain authoritative. A custom IAM administrator can manage identities
without automatically gaining access to investigation evidence.

## Responsive workspace

Desktop presents user lifecycle and user details side by side. Tablet collapses
administration panels into an adaptive layout. Mobile follows User List, User
Details, Sessions, then Security Status, with touch-sized controls and no
frontend-only authorization assumptions.
