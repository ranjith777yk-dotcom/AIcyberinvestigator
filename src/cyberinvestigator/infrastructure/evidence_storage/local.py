"""Safe local filesystem adapter for evidence byte preservation.

Security hardening goals (deletion path):
- Detect symlinks and junctions and refuse to delete through them.
- Canonical path validation: ensure deletions remain within the configured root.
- Trusted ID -> Path mapping to prevent deletion of arbitrary files.

Public API is preserved: store(...) and remove(storage_path) signatures and return
shape are unchanged.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import stat
from pathlib import Path
from typing import BinaryIO, Final
from uuid import UUID, uuid4

from cyberinvestigator.application.ports.evidence_storage import StoredEvidenceFile
from cyberinvestigator.shared.exceptions import EvidenceStorageError


class LocalEvidenceStorage:
    """Store evidence streams atomically below one configured root directory.

    This adapter deliberately performs no file inspection or analysis. It copies
    bytes, computes a SHA-256 digest during that copy, and records a filename-based
    MIME type only.

    Deletion hardening:
    The remove(storage_path) method treats the provided storage_path as an opaque
    identifier derived from this adapter. It resolves it using a trusted mapping
    rooted at the configured evidence storage directory.
    """

    _CHUNK_SIZE: Final[int] = 1024 * 1024

    def __init__(self, root_directory: Path, *, max_bytes: int | None = None) -> None:
        """Create storage rooted at an explicit, caller-controlled path."""
        self._root_directory = root_directory.resolve()
        self._root_directory.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes

    def store(
        self,
        *,
        case_id: UUID,
        filename: str,
        content: BinaryIO,
        media_type: str | None = None,
    ) -> StoredEvidenceFile:
        """Copy a stream atomically and return its path, size, hash, and MIME type."""
        safe_name = Path(filename).name
        suffix = Path(safe_name).suffix.lower()

        case_directory = self._root_directory / str(case_id)
        case_directory.mkdir(parents=True, exist_ok=True)

        destination = case_directory / f"{uuid4().hex}{suffix}"
        temporary = destination.with_suffix(f"{destination.suffix}.partial")

        digest = hashlib.sha256()
        size_bytes = 0

        try:
            # Open a new file only (prevents clobbering existing files).
            with temporary.open("xb") as target:
                while chunk := content.read(self._CHUNK_SIZE):
                    if not isinstance(chunk, bytes):
                        raise TypeError("Evidence content must yield bytes.")
                    if self._max_bytes is not None and size_bytes + len(chunk) > self._max_bytes:
                        raise EvidenceStorageError("Evidence exceeds the configured custody size limit.")
                    digest.update(chunk)
                    target.write(chunk)
                    size_bytes += len(chunk)

                target.flush()
                os.fsync(target.fileno())

            # Atomic replace on same filesystem.
            temporary.replace(destination)
            destination.chmod(0o600)

        except (OSError, TypeError, EvidenceStorageError) as error:
            self._remove_if_present(temporary)
            self._remove_if_present(destination)
            if isinstance(error, EvidenceStorageError):
                raise
            raise EvidenceStorageError("Evidence file could not be stored safely.") from error

        # Backward compatibility: preserve the same storage_path format returned
        # by the previous implementation.
        storage_path = str(destination.relative_to(self._root_directory))
        return StoredEvidenceFile(
            storage_path=storage_path,
            size_bytes=size_bytes,
            sha256=digest.hexdigest(),
            media_type=media_type or mimetypes.guess_type(safe_name)[0] or "application/octet-stream",
        )

    def remove(self, storage_path: str) -> None:
        """Remove a stored file after a failed metadata transaction, if it is safe.

        This method is hardened against symlink/junction traversal.
        """
        # Trusted ID -> Path mapping: storage_path must match the adapter-owned
        # relative path layout: <case_id>/<filename>.
        relative = self._trusted_relative_id(storage_path)
        candidate = self._resolve_and_validate_with_canonical_path(relative)

        # Reject deletion when any path component is a symlink/junction.
        self._reject_if_path_contains_restricted_links(relative, candidate)

        try:
            candidate.unlink(missing_ok=True)
        except OSError as error:
            raise EvidenceStorageError("Stored evidence file could not be removed safely.") from error

    def _trusted_relative_id(self, storage_path: str) -> Path:
        """Parse and validate storage_path as an adapter-owned relative identifier."""
        try:
            # Enforce no absolute paths and no parent traversal.
            if not storage_path or storage_path.startswith(("/", "\\")):
                raise EvidenceStorageError("Evidence storage path is invalid.")

            # Path parts must be exactly: case_id/filename
            # storage_path is returned by store(): <case_uuid>/<uuid>.ext
            candidate_parts = Path(storage_path).parts
            if len(candidate_parts) != 2:
                raise EvidenceStorageError("Evidence storage path is invalid.")

            case_part, filename_part = candidate_parts
            # Stronger validation that case id is a UUID.
            UUID(case_part)
            if not filename_part:
                raise EvidenceStorageError("Evidence storage path is invalid.")

            # Prevent weird separators/empty segments.
            if "." in case_part and case_part != str(UUID(case_part)):
                raise EvidenceStorageError("Evidence storage path is invalid.")

            # filename must not include path traversal.
            if filename_part in {".", ".."} or Path(filename_part).parts != (filename_part,):
                raise EvidenceStorageError("Evidence storage path is invalid.")

            # Build a relative path under root.
            return Path(case_part) / filename_part

        except ValueError as error:
            raise EvidenceStorageError("Evidence storage path is invalid.") from error

    def _resolve_and_validate_with_canonical_path(self, relative: Path) -> Path:
        """Resolve candidate with canonical path validation within root."""
        candidate = (self._root_directory / relative).resolve()

        # Canonical path validation: must stay within evidence root.
        if candidate == self._root_directory or self._root_directory not in candidate.parents:
            raise EvidenceStorageError("Evidence storage path is outside the configured evidence root.")
        return candidate

    def _reject_if_path_contains_restricted_links(self, relative: Path, resolved: Path) -> None:
        """Detect symlinks and junctions for every component along the deletion path."""

        # Walk each component from root to destination using the *non-resolved* path
        # (so we can detect link types via lstat).
        current = self._root_directory
        for part in relative.parts:
            next_path = current / part

            # lstat: does not follow symlinks.
            try:
                st = next_path.lstat()
            except FileNotFoundError:
                # If the file doesn't exist, treat as safe no-op for compatibility.
                return

            # Symlink detection (POSIX and Windows).
            if stat.S_ISLNK(st.st_mode):
                raise EvidenceStorageError("Evidence storage path contains a symlink; deletion refused.")

            # Junction detection (Windows): reparse point that is not a symlink.
            # In Python on Windows, junctions typically appear as FILE_ATTRIBUTE_REPARSE_POINT.
            if bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                raise EvidenceStorageError("Evidence storage path contains a reparse point; deletion refused.")

            # Some Windows implementations encode junction/symlink as reparse points.
            # The pathlib/os stat module on Windows may not expose a direct flag, but we
            # can still catch via follow/compare behavior where possible.
            try:
                # If resolving changes the component identity, it's likely a link.
                if next_path.resolve(strict=False) != next_path:
                    # But only treat as unsafe if next_path itself is not a directory move
                    # within root. For simplicity and safety: refuse any component whose
                    # resolution differs.
                    raise EvidenceStorageError(
                        "Evidence storage path contains a junction/reparse link; deletion refused."
                    )
            except EvidenceStorageError:
                raise
            except OSError:
                # If we can't resolve component safely, refuse.
                raise EvidenceStorageError(
                    "Evidence storage path could not be validated for junction/symlink safety."
                ) from None

            current = next_path

        # Finally ensure the resolved target still points within root and is not itself a symlink.
        try:
            target_lstat = resolved.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(target_lstat.st_mode):
            raise EvidenceStorageError("Evidence target is a symlink; deletion refused.")

    @staticmethod
    def _remove_if_present(path: Path) -> bool:
        """Best-effort cleanup of an incomplete temporary transfer."""
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:
            return False
