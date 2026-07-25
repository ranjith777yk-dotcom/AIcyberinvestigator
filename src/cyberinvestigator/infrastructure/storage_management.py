"""Local storage health, verified backups, and disaster-recovery planning."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


class StorageOperationError(RuntimeError):
    """Raised when a storage operation cannot preserve integrity guarantees."""


@dataclass(frozen=True, slots=True)
class ManagedRoot:
    name: str
    path: Path
    classification: str


class LocalStorageManager:
    """Inspect and back up configured local roots without executing evidence."""

    def __init__(
        self,
        *,
        instance_root: Path,
        evidence_root: Path,
        reports_root: Path,
        logs_root: Path,
        backup_root: Path,
        database_path: Path | None,
    ) -> None:
        self.instance_root = instance_root.resolve()
        self.backup_root = backup_root.resolve()
        self.database_path = database_path.resolve() if database_path else None
        self._backup_lock = threading.Lock()
        self.roots = (
            ManagedRoot("Evidence quarantine", evidence_root.resolve(), "forensic_evidence"),
            ManagedRoot("Reports", reports_root.resolve(), "investigation_output"),
            ManagedRoot("Operational logs", logs_root.resolve(), "operational"),
        )
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self._restrict_directory(self.backup_root)

    def workspace(self) -> dict[str, object]:
        roots = [self._root_health(root) for root in self.roots]
        capacity = self._capacity(self.instance_root)
        return {
            "provider": {
                "id": "local-filesystem",
                "name": "Local filesystem",
                "type": "local",
                "status": "available" if all(item["available"] for item in roots) else "degraded",
                "configured": True,
                "capabilities": {
                    "atomic_writes": True,
                    "content_hashing": "sha256",
                    "versioning": False,
                    "object_lock": False,
                    "server_side_encryption": False,
                },
            },
            "roots": roots,
            "capacity": capacity,
            "backups": self.list_backups(),
            "encryption": {
                "at_rest": {
                    "status": "unverified",
                    "detail": "Application-level evidence encryption is not enabled; use an encrypted deployment volume.",
                },
                "in_transit": {
                    "status": "deployment_managed",
                    "detail": "TLS termination is managed by the deployment proxy and cannot be verified from storage.",
                },
            },
        }

    def create_backup(self) -> dict[str, object]:
        if not self._backup_lock.acquire(blocking=False):
            raise StorageOperationError("A backup is already running in this application process.")
        try:
            return self._create_backup_locked()
        finally:
            self._backup_lock.release()

    def _create_backup_locked(self) -> dict[str, object]:
        backup_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
        temporary = self.backup_root / f".{backup_id}.partial"
        destination = self.backup_root / backup_id
        if temporary.exists() or destination.exists():
            raise StorageOperationError("Backup identifier collision.")
        temporary.mkdir(parents=True)
        self._restrict_directory(temporary)
        try:
            files: list[dict[str, object]] = []
            if self.database_path is not None and self.database_path.is_file():
                database_target = temporary / "database" / "cyberinvestigator.db"
                database_target.parent.mkdir(parents=True)
                self._backup_sqlite(self.database_path, database_target)
                files.append(self._file_manifest(database_target, temporary))
            elif self.database_path is not None:
                raise StorageOperationError("Configured SQLite database file is unavailable.")

            for root in self.roots[:2]:
                if not root.path.exists():
                    continue
                target_root = temporary / "data" / root.name.lower().replace(" ", "-")
                self._copy_tree(root.path, target_root)
                files.extend(self._manifests(target_root, temporary))

            manifest = {
                "schema_version": 1,
                "backup_id": backup_id,
                "created_at": datetime.now(UTC).isoformat(),
                "status": "verified",
                "provider": "local-filesystem",
                "file_count": len(files),
                "size_bytes": sum(int(item["size_bytes"]) for item in files),
                "files": files,
            }
            (temporary / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            verification = self._verify_directory(temporary)
            if verification["valid"] is not True:
                raise StorageOperationError("Backup verification failed before publication.")
            temporary.replace(destination)
            self._write_verification(destination, verification)
            return {**manifest, "verification": verification}
        except Exception as error:
            shutil.rmtree(temporary, ignore_errors=True)
            if isinstance(error, StorageOperationError):
                raise
            raise StorageOperationError("Backup could not be created safely.") from error

    def list_backups(self) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        try:
            candidates = sorted(self.backup_root.iterdir(), key=lambda item: item.name, reverse=True)
        except OSError:
            return records
        for candidate in candidates:
            if not candidate.is_dir() or candidate.name.startswith("."):
                continue
            manifest_path = candidate / "manifest.json"
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                records.append(
                    {
                        "backup_id": candidate.name,
                        "status": "unverified",
                        "created_at": None,
                        "file_count": None,
                        "size_bytes": None,
                    }
                )
                continue
            verification = self._read_verification(candidate)
            records.append(
                {key: manifest.get(key) for key in ("backup_id", "created_at", "status", "file_count", "size_bytes")}
                | {
                    "last_verification": verification,
                    "status": (
                        "verification_failed"
                        if verification and verification.get("valid") is False
                        else "verified_at_creation"
                    ),
                }
            )
        return records[:100]

    def verify_backup(self, backup_id: str) -> dict[str, object]:
        directory = self._backup_directory(backup_id)
        result = self._verify_directory(directory)
        self._write_verification(directory, result)
        return result

    def restore_plan(self, backup_id: str) -> dict[str, object]:
        verification = self.verify_backup(backup_id)
        if verification["valid"] is not True:
            raise StorageOperationError("Restore plan refused because backup verification failed.")
        return {
            "backup_id": backup_id,
            "status": "ready_for_offline_restore",
            "verified_at": verification["verified_at"],
            "verification": verification,
            "requires_maintenance_window": True,
            "automatic_restore_executed": False,
            "instructions": [
                "Place the application in maintenance mode.",
                "Stop application workers before replacing persistent data.",
                "Run the offline recovery command against this verified backup.",
                "Start services and run database, evidence, and audit integrity checks.",
            ],
        }

    def _verify_directory(self, directory: Path) -> dict[str, object]:
        manifest_path = directory / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected = manifest.get("files")
            if not isinstance(expected, list):
                raise ValueError("manifest files are invalid")
            failures: list[dict[str, str]] = []
            checked = 0
            for record in expected:
                relative = str(record.get("path") or "")
                target = (directory / relative).resolve()
                if directory.resolve() not in target.parents or not target.is_file():
                    failures.append({"path": relative, "reason": "missing_or_invalid"})
                    continue
                digest = self._sha256(target)
                if digest != record.get("sha256") or target.stat().st_size != record.get("size_bytes"):
                    failures.append({"path": relative, "reason": "integrity_mismatch"})
                    continue
                checked += 1
            return {
                "valid": not failures and checked == len(expected),
                "files_checked": checked,
                "failures": failures,
                "verified_at": datetime.now(UTC).isoformat(),
            }
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            return {
                "valid": False,
                "files_checked": 0,
                "failures": [{"path": "manifest.json", "reason": "manifest_unavailable_or_invalid"}],
                "verified_at": datetime.now(UTC).isoformat(),
            }

    def _backup_directory(self, backup_id: str) -> Path:
        if not backup_id or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for character in backup_id
        ):
            raise StorageOperationError("Backup identifier is invalid.")
        candidate = (self.backup_root / backup_id).resolve()
        if self.backup_root not in candidate.parents or not candidate.is_dir():
            raise StorageOperationError("Backup was not found.")
        return candidate

    @staticmethod
    def _backup_sqlite(source: Path, destination: Path) -> None:
        with closing(sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)) as source_connection:
            with closing(sqlite3.connect(destination)) as destination_connection:
                source_connection.backup(destination_connection)
                destination_connection.commit()

    @staticmethod
    def _copy_tree(source: Path, destination: Path) -> None:
        for path in source.rglob("*"):
            if path.is_symlink():
                raise StorageOperationError("Backup refused a symbolic link in a managed storage root.")
            relative = path.relative_to(source)
            target = destination / relative
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)

    def _manifests(self, root: Path, base: Path) -> list[dict[str, object]]:
        return [self._file_manifest(path, base) for path in root.rglob("*") if path.is_file()]

    def _file_manifest(self, path: Path, base: Path) -> dict[str, object]:
        return {
            "path": path.relative_to(base).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": self._sha256(path),
        }

    @staticmethod
    def _write_verification(directory: Path, result: dict[str, object]) -> None:
        path = directory / ".verification.json"
        path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _read_verification(directory: Path) -> dict[str, object] | None:
        try:
            payload = json.loads((directory / ".verification.json").read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _restrict_directory(path: Path) -> None:
        try:
            path.chmod(0o700)
        except OSError:
            pass

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _capacity(path: Path) -> dict[str, object]:
        try:
            usage = shutil.disk_usage(path)
            return {
                "status": "available",
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_percent": round((usage.used / usage.total) * 100, 2) if usage.total else None,
                "scope": "filesystem_containing_instance_root",
            }
        except OSError:
            return {"status": "unavailable", "reason": "Filesystem capacity could not be read."}

    @staticmethod
    def _root_health(root: ManagedRoot) -> dict[str, object]:
        available = root.path.is_dir()
        file_count = 0
        size_bytes = 0
        if available:
            try:
                for path in root.path.rglob("*"):
                    if path.is_file() and not path.is_symlink():
                        file_count += 1
                        size_bytes += path.stat().st_size
            except OSError:
                available = False
        return {
            "name": root.name,
            "classification": root.classification,
            "available": available,
            "writable": available and os.access(root.path, os.W_OK),
            "file_count": file_count if available else None,
            "size_bytes": size_bytes if available else None,
        }
