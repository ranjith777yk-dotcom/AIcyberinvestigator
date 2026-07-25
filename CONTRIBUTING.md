# Contributing to CyberInvestigator

CyberInvestigator is a security-sensitive application. Changes must preserve
authentication, authorization, auditability, evidence integrity, API
compatibility, and existing routes.

The normative engineering contract is
[docs/engineering-standards.md](docs/engineering-standards.md). Architecture,
security, design-system, responsive, and information-architecture decisions
are linked from [docs/developer-guide.md](docs/developer-guide.md).

## Local quality gate

From the repository root:

```powershell
python -m pip install -r requirements-dev.txt
python -m ruff check src tests
python -m ruff format --check src tests
python -m compileall -q src
python -m pytest
```

Format changed Python files with `python -m ruff format <paths>` before running
the gate. Do not weaken a check to make a change pass.

## Change workflow

1. Open a focused issue or describe the user outcome and acceptance criteria.
2. Identify compatibility, security, evidence-handling, RBAC, and migration
   risks before implementation.
3. Keep changes small and cohesive. Separate refactoring from behavior changes
   where practical.
4. Add or update tests and documentation in the same change.
5. Complete the pull-request template and obtain the required review.

Use Conventional Commit subjects, for example:

```text
feat(evidence): add asynchronous analysis status
fix(authz): enforce report export permission
refactor(ai): isolate provider selection
docs(architecture): record job queue boundary
```

Never commit credentials, tokens, evidence, production data, generated runtime
state, or sensitive logs. Report suspected vulnerabilities privately to the
repository maintainers; do not publish exploit details in an issue.
