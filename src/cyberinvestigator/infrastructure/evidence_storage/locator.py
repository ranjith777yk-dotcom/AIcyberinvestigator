"""Canonical evidence path resolution across current and legacy storage roots."""

from __future__ import annotations

from pathlib import Path

from cyberinvestigator.shared.exceptions import EvidenceStorageError


class EvidenceFileLocator:
    """Resolve opaque storage identifiers without permitting path traversal."""

    def __init__(self, primary_root: Path, legacy_roots: tuple[Path, ...] = ()) -> None:
        self._primary_root = primary_root.resolve()
        self._legacy_roots = tuple(root.resolve() for root in legacy_roots if root.resolve() != self._primary_root)

    def resolve(self, storage_path: str, *, must_exist: bool = True) -> Path:
        """Resolve a stored evidence identifier under an approved root.

        The primary quarantine root is checked first. Legacy roots provide
        backward-compatible access to evidence registered before quarantine
        became the default.
        """
        relative = self._validate_identifier(storage_path)
        candidates = [self._safe_candidate(root, relative) for root in (self._primary_root, *self._legacy_roots)]
        if not must_exist:
            return candidates[0]
        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        raise FileNotFoundError("Evidence custody file is unavailable.")

    @staticmethod
    def _validate_identifier(storage_path: str) -> Path:
        relative = Path(str(storage_path or ""))
        if (
            not storage_path
            or relative.is_absolute()
            or len(relative.parts) != 2
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise EvidenceStorageError("Evidence storage identifier is invalid.")
        return relative

    @staticmethod
    def _safe_candidate(root: Path, relative: Path) -> Path:
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise EvidenceStorageError("Evidence storage path contains a symbolic link.")
        candidate = (root / relative).resolve()
        if candidate == root or root not in candidate.parents:
            raise EvidenceStorageError("Evidence storage identifier escapes its approved root.")
        return candidate
