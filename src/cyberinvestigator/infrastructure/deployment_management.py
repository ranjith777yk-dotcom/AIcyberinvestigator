"""Truthful release metadata and repository delivery capability inspection."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path


class DeploymentInspector:
    """Inspect runtime and repository state without claiming external pipeline runs."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()

    def workspace(self, *, environment: str, last_verification: object, release_catalog: object) -> dict[str, object]:
        release = self.current_release(environment)
        workflows = self._workflows()
        catalog = release_catalog if isinstance(release_catalog, list) else []
        releases = [release]
        seen = {str(release["version"])}
        for item in catalog:
            if isinstance(item, dict) and str(item.get("version") or "") not in seen:
                releases.append(item)
                seen.add(str(item.get("version")))
        return {
            "collected_at": datetime.now(UTC).isoformat(),
            "deployment_status": {
                "status": "running",
                "environment": environment,
                "containerized": Path("/.dockerenv").exists(),
                "release": release,
                "last_verification": last_verification,
            },
            "pipelines": {
                "provider": "github_actions" if workflows else None,
                "definitions": workflows,
                "active_runs": None,
                "history_status": "unavailable",
                "history_detail": "No authenticated CI provider API is configured at runtime.",
            },
            "failed_builds": {
                "status": "unavailable",
                "items": [],
                "detail": "Build history requires a connected CI provider.",
            },
            "recent_releases": releases,
            "rollback": {
                "strategy": "immutable_image_redeploy",
                "automatic": False,
                "candidates": [item for item in releases[1:] if item.get("digest")],
                "detail": "Rollback requires a recorded immutable image digest and an environment deployment adapter.",
            },
            "security": self._security_capabilities(workflows),
            "infrastructure_as_code": {
                "status": "prepared",
                "container": (self.project_root / "Dockerfile").is_file(),
                "compose": (self.project_root / "docker-compose.yml").is_file(),
                "terraform": self._contains("infra", "*.tf"),
                "kubernetes": self._contains("deploy", "*deployment*.yaml"),
            },
            "environments": [
                {"name": name, "active": name == environment, "configured": True}
                for name in ("development", "testing", "production")
            ],
        }

    @staticmethod
    def current_release(environment: str) -> dict[str, object]:
        return {
            "version": os.getenv("RELEASE_VERSION") or "unversioned",
            "git_sha": os.getenv("GIT_SHA") or None,
            "build_time": os.getenv("BUILD_TIME") or None,
            "digest": os.getenv("IMAGE_DIGEST") or None,
            "environment": environment,
            "status": "current_runtime",
        }

    def _workflows(self) -> list[dict[str, object]]:
        directory = self.project_root / ".github" / "workflows"
        if not directory.is_dir():
            return []
        records = []
        for path in sorted((*directory.glob("*.yml"), *directory.glob("*.yaml"))):
            try:
                content = path.read_bytes()
                updated_at = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
            except OSError:
                continue
            records.append(
                {
                    "name": path.name,
                    "status": "defined",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "updated_at": updated_at,
                    "run_status": "unavailable",
                }
            )
        return records

    def _security_capabilities(self, workflows: list[dict[str, object]]) -> dict[str, object]:
        contents = ""
        for item in workflows:
            try:
                contents += (self.project_root / ".github" / "workflows" / str(item["name"])).read_text(
                    encoding="utf-8"
                )
            except OSError:
                continue
        return {
            "dependency_audit": "configured" if "pip_audit" in contents else "unavailable",
            "static_analysis": "configured" if "bandit" in contents else "unavailable",
            "code_scanning": "configured" if "codeql-action" in contents else "unavailable",
            "container_provenance": "configured" if "attest-build-provenance" in contents else "unavailable",
            "scan_results": None,
            "scan_results_detail": "External scan results are not available without a CI provider connection.",
        }

    def _contains(self, directory: str, pattern: str) -> bool:
        root = self.project_root / directory
        if not root.is_dir():
            return False
        try:
            return next(root.rglob(pattern), None) is not None
        except OSError:
            return False
