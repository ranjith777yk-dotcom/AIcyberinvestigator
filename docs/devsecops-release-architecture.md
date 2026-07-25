# DevSecOps and release architecture

## Trust boundaries

Source control, CI execution, the container registry, deployment environments,
and the running application are separate trust boundaries. Repository workflow
definitions prove only that a gate is configured; they do not prove a run
passed. The application therefore reports external pipeline runs, failed builds,
and scan results as unavailable until an authenticated provider is connected.

Runtime release identity comes only from `RELEASE_VERSION`, `GIT_SHA`,
`BUILD_TIME`, and optional `IMAGE_DIGEST` injected during delivery. Unknown
values remain visibly unavailable.

## Delivery flow

```text
change
  → lint / format / compile / tests
  → dependency audit / SAST / CodeQL
  → production container build
  → protected release environment
  → immutable registry image + provenance
  → environment-specific deployment adapter
  → liveness / readiness / authenticated verification
```

The current repository implements through immutable registry delivery. It does
not contain credentials or pretend to deploy to a cloud target.

## Security controls

- Workflows use least-privilege default permissions and scoped release
  permissions.
- Release jobs use GitHub environment protection and serialized concurrency.
- Secrets come from environment protection or runtime secret management.
- `.env` is excluded from source control and Docker build context.
- The container runs without root, drops capabilities, uses a read-only root
  filesystem, and prevents privilege escalation.
- Build metadata and an attested image digest support traceability.
- Deployment verification and rollback-plan actions enforce server-side
  `deployments.manage` and administrator RBAC.
- Verification failures generate persisted alerts and notifications.

## Rollback

Rollback candidates must exist in the persisted release catalog and include an
immutable digest. The web application creates and audits a plan but does not
mutate its own runtime. This prevents a compromised web process from controlling
the deployment plane.

No recovery time, deployment frequency, lead time, failure rate, pipeline
history, or scan result is inferred.

## Infrastructure as Code preparation

The container and Compose contracts provide the first portable deployment
boundary. Terraform and Kubernetes are reported as not configured until actual
definitions exist under dedicated `infra/` or `deploy/` directories. Future IaC
must keep evidence storage non-executable, encrypted, persistent, isolated from
the web root, and covered by verified backup policy.
