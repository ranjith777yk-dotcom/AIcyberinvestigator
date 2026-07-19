"""Deterministic forensic file analysis for evidence triage."""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import io
import lzma
import math
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final


@dataclass(frozen=True, slots=True)
class ForensicAnalysisResult:
    """JSON-safe forensic analysis result."""

    summary: str
    report: dict[str, object]


class ForensicAnalyzer:
    """Analyze evidence bytes without executing or trusting the artifact."""

    MAX_BYTES: Final[int] = 8 * 1024 * 1024
    MAX_DEPTH: Final[int] = 4
    MAX_CHILDREN: Final[int] = 40
    MAX_STRINGS: Final[int] = 80
    _FLAG_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"(?i)(flag|ctf|picoctf|htb|tryhackme)\{[^}\r\n]{2,120}\}|[A-Z0-9_]{2,32}\{[^}\r\n]{2,120}\}"
    )
    _PRINTABLE_PATTERN: Final[re.Pattern[bytes]] = re.compile(rb"[\x20-\x7e]{4,}")
    _MAGIC: Final[tuple[tuple[bytes, str], ...]] = (
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"PK\x05\x06", "Empty ZIP archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
        (b"\x1f\x8b", "Gzip compressed data"),
        (b"BZh", "Bzip2 compressed data"),
        (b"\xfd7zXZ\x00", "XZ compressed data"),
        (b"MZ", "Windows PE executable"),
        (b"\x7fELF", "ELF executable"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
    )

    def analyze_path(
        self, path: Path, *, evidence_number: str, original_filename: str, sha256: str
    ) -> ForensicAnalysisResult:
        """Analyze one stored evidence file and return a full report."""
        data = path.read_bytes()[: self.MAX_BYTES]
        truncated = path.stat().st_size > len(data)
        root = self._analyze_bytes(data, original_filename, depth=0)
        findings = self._flatten_findings(root)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence": {
                "evidence_number": evidence_number,
                "original_filename": original_filename,
                "stored_path": str(path),
                "sha256": sha256,
                "bytes_analyzed": len(data),
                "truncated": truncated,
            },
            "chain_of_custody": [
                "Evidence bytes were read from immutable local custody storage.",
                "The persisted SHA-256 hash was retained and included in this report.",
                "Analysis was read-only; extracted children were analyzed in memory.",
            ],
            "root": root,
            "findings": findings,
            "explanation": self._explain(findings, root),
        }
        summary = self._summary(findings, root)
        return ForensicAnalysisResult(summary=summary, report=report)

    def _analyze_bytes(self, data: bytes, name: str, *, depth: int) -> dict[str, object]:
        magic = self._magic_name(data)
        strings = self._strings(data)
        decoded = self._decode_candidates(data, strings)
        flags = self._find_flags(strings + [item["decoded_preview"] for item in decoded])
        node: dict[str, object] = {
            "name": name,
            "size_bytes": len(data),
            "magic_bytes": data[:16].hex(" ").upper(),
            "file_signature": magic,
            "entropy": round(self._entropy(data), 4),
            "encoding": self._detect_encoding(data),
            "compression": self._detect_compression(data),
            "archive": self._detect_archive(data, name),
            "encryption_indicators": self._encryption_indicators(data, name, magic),
            "steganography_indicators": self._stego_indicators(data, strings),
            "embedded_file_indicators": self._embedded_indicators(data),
            "metadata": self._metadata(data, name),
            "hidden_strings": strings[: self.MAX_STRINGS],
            "decoded_payloads": decoded,
            "flags": flags,
            "children": [],
        }
        if depth < self.MAX_DEPTH:
            node["children"] = self._extract_children(data, name, depth=depth)
        return node

    def _extract_children(self, data: bytes, name: str, *, depth: int) -> list[dict[str, object]]:
        children: list[dict[str, object]] = []
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist()[: self.MAX_CHILDREN]:
                    if info.is_dir():
                        continue
                    try:
                        child = archive.read(info, pwd=None)[: self.MAX_BYTES]
                    except (RuntimeError, OSError, zipfile.BadZipFile):
                        children.append(
                            {
                                "name": info.filename,
                                "error": "Could not extract; archive member may be encrypted or corrupt.",
                            }
                        )
                        continue
                    children.append(self._analyze_bytes(child, info.filename, depth=depth + 1))
            return children
        try:
            fileobj = io.BytesIO(data)
            with tarfile.open(fileobj=fileobj) as archive:
                for member in archive.getmembers()[: self.MAX_CHILDREN]:
                    if not member.isfile():
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    children.append(self._analyze_bytes(extracted.read(self.MAX_BYTES), member.name, depth=depth + 1))
            return children
        except tarfile.TarError:
            return children
        for label, decompressor in (
            ("gzip", gzip.decompress),
            ("bzip2", bz2.decompress),
            ("xz", lzma.decompress),
            ("zlib", zlib.decompress),
        ):
            try:
                expanded = decompressor(data)[: self.MAX_BYTES]
            except (OSError, EOFError, lzma.LZMAError, zlib.error):
                continue
            children.append(self._analyze_bytes(expanded, f"{name}.{label}.decompressed", depth=depth + 1))
            break
        return children

    @classmethod
    def _magic_name(cls, data: bytes) -> str:
        for signature, name in cls._MAGIC:
            if data.startswith(signature):
                return name
        return "Unknown"

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts if count)

    def _strings(self, data: bytes) -> list[str]:
        return [
            match.decode("utf-8", errors="replace")
            for match in self._PRINTABLE_PATTERN.findall(data)[: self.MAX_STRINGS]
        ]

    @staticmethod
    def _detect_encoding(data: bytes) -> dict[str, object]:
        for encoding in ("utf-8", "utf-16", "utf-32"):
            try:
                data.decode(encoding)
            except UnicodeError:
                continue
            return {"detected": True, "encoding": encoding}
        ascii_ratio = sum(1 for byte in data if byte in b"\t\r\n" or 32 <= byte <= 126) / max(len(data), 1)
        return {
            "detected": ascii_ratio > 0.85,
            "encoding": "ascii-compatible" if ascii_ratio > 0.85 else "binary/unknown",
        }

    def _decode_candidates(self, data: bytes, strings: list[str]) -> list[dict[str, str]]:
        candidates = []
        for value in strings[:30]:
            compact = re.sub(r"\s+", "", value)
            if len(compact) < 8:
                continue
            for label, decoder in (
                ("base64", base64.b64decode),
                ("base32", base64.b32decode),
                ("hex", binascii.unhexlify),
            ):
                try:
                    decoded = decoder(compact, validate=True) if label == "base64" else decoder(compact)
                except (binascii.Error, ValueError):
                    continue
                if decoded and any(32 <= byte <= 126 for byte in decoded):
                    candidates.append(
                        {
                            "encoding": label,
                            "source": value[:120],
                            "decoded_preview": decoded[:300].decode("utf-8", errors="replace"),
                        }
                    )
                    break
        if data.startswith(b"data:") and b";base64," in data[:200]:
            _, payload = data.split(b";base64,", 1)
            try:
                decoded = base64.b64decode(payload, validate=False)
                candidates.append(
                    {
                        "encoding": "data-url-base64",
                        "source": "data URL",
                        "decoded_preview": decoded[:300].decode("utf-8", errors="replace"),
                    }
                )
            except binascii.Error:
                return candidates[:10]
        return candidates[:10]

    def _find_flags(self, values: list[str]) -> list[str]:
        found: list[str] = []
        for value in values:
            for match in self._FLAG_PATTERN.finditer(value):
                text = match.group(0)
                if text not in found:
                    found.append(text)
        return found[:25]

    @staticmethod
    def _detect_compression(data: bytes) -> dict[str, object]:
        mapping = (
            (b"\x1f\x8b", "gzip"),
            (b"BZh", "bzip2"),
            (b"\xfd7zXZ\x00", "xz"),
            (b"x\x9c", "zlib"),
            (b"x\xda", "zlib"),
        )
        for signature, label in mapping:
            if data.startswith(signature):
                return {"detected": True, "type": label}
        return {"detected": False, "type": None}

    @staticmethod
    def _detect_archive(data: bytes, name: str) -> dict[str, object]:
        archive_type = None
        if zipfile.is_zipfile(io.BytesIO(data)):
            archive_type = "zip"
        elif data.startswith(b"Rar!\x1a\x07"):
            archive_type = "rar"
        elif data.startswith(b"7z\xbc\xaf'\x1c"):
            archive_type = "7z"
        else:
            try:
                with tarfile.open(fileobj=io.BytesIO(data)):
                    archive_type = "tar"
            except tarfile.TarError:
                archive_type = None
        return {"detected": archive_type is not None, "type": archive_type, "filename_hint": Path(name).suffix.lower()}

    @staticmethod
    def _encryption_indicators(data: bytes, name: str, magic: str) -> list[str]:
        indicators = []
        if len(data) > 1024 and ForensicAnalyzer._entropy(data) > 7.5:
            indicators.append("High entropy may indicate encryption, compression, or packed binary data.")
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if any(info.flag_bits & 0x1 for info in archive.infolist()):
                    indicators.append("ZIP member encryption flag is set.")
        if "encrypted" in name.lower() or "Encrypted" in magic:
            indicators.append("Filename or signature hints at encryption.")
        return indicators

    @staticmethod
    def _stego_indicators(data: bytes, strings: list[str]) -> list[str]:
        indicators = []
        if data.startswith(b"\xff\xd8") and b"\xff\xd9" in data:
            end = data.rfind(b"\xff\xd9")
            if end + 2 < len(data):
                indicators.append("JPEG has trailing bytes after end marker.")
        if data.startswith(b"\x89PNG") and b"IEND" in data:
            end = data.rfind(b"IEND")
            if end + 8 < len(data):
                indicators.append("PNG has trailing bytes after IEND chunk.")
        if any("steghide" in value.lower() or "outguess" in value.lower() for value in strings):
            indicators.append("Known steganography tool string found.")
        return indicators

    @staticmethod
    def _embedded_indicators(data: bytes) -> list[str]:
        indicators = []
        for signature, label in ForensicAnalyzer._MAGIC:
            count = data.count(signature)
            if count > 1:
                indicators.append(f"Multiple {label} signatures found ({count}).")
        if b"PK\x03\x04" in data and not data.startswith(b"PK\x03\x04"):
            indicators.append("Embedded ZIP signature found away from file start.")
        if b"%PDF-" in data and not data.startswith(b"%PDF-"):
            indicators.append("Embedded PDF signature found away from file start.")
        return indicators

    @staticmethod
    def _metadata(data: bytes, name: str) -> dict[str, object]:
        metadata: dict[str, object] = {"extension": Path(name).suffix.lower() or None}
        if data.startswith(b"%PDF-"):
            match = re.search(rb"%PDF-(\d\.\d)", data[:32])
            if match:
                metadata["pdf_version"] = match.group(1).decode("ascii")
            metadata["pdf_objects"] = len(re.findall(rb"\bobj\b", data))
        if data.startswith(b"\x89PNG"):
            metadata["png_chunks"] = [
                chunk.decode("ascii", errors="ignore") for chunk in re.findall(rb"[A-Za-z]{4}", data[:1024])[:20]
            ]
        if data.startswith(b"\xff\xd8"):
            metadata["jpeg_markers_seen"] = data[:2048].count(b"\xff")
        return metadata

    def _flatten_findings(self, root: dict[str, object]) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []

        def walk(node: dict[str, object], path: str) -> None:
            for flag in node.get("flags", []):
                findings.append({"severity": "high", "path": path, "type": "ctf_flag", "detail": flag})
            for key in ("encryption_indicators", "steganography_indicators", "embedded_file_indicators"):
                for detail in node.get(key, []):
                    findings.append({"severity": "medium", "path": path, "type": key, "detail": detail})
            if node.get("archive", {}).get("detected"):
                findings.append(
                    {"severity": "info", "path": path, "type": "archive", "detail": node["archive"]["type"]}
                )
            if node.get("compression", {}).get("detected"):
                findings.append(
                    {"severity": "info", "path": path, "type": "compression", "detail": node["compression"]["type"]}
                )
            for child in node.get("children", []):
                if isinstance(child, dict):
                    walk(child, f"{path}/{child.get('name', 'child')}")

        walk(root, str(root.get("name", "root")))
        return findings

    @staticmethod
    def _summary(findings: list[dict[str, object]], root: dict[str, object]) -> str:
        flags = sum(1 for item in findings if item["type"] == "ctf_flag")
        return (
            f"{root['file_signature']} analyzed; entropy {root['entropy']}. "
            f"{len(findings)} notable findings, {flags} possible flags, {len(root.get('children', []))} extracted child item(s)."
        )

    @staticmethod
    def _explain(findings: list[dict[str, object]], root: dict[str, object]) -> list[str]:
        explanation = [
            f"Magic bytes identify the root artifact as: {root['file_signature']}.",
            f"Entropy is {root['entropy']}; values near 8.0 often indicate compressed, encrypted, or packed data.",
            "Printable strings and supported encodings were inspected without executing content.",
        ]
        if root.get("children"):
            explanation.append(
                "Archive or compression content was extracted recursively in memory and analyzed with the same checks."
            )
        if findings:
            explanation.append("Findings are ranked by indicator type and include path context for extracted children.")
        else:
            explanation.append(
                "No strong hidden-content, flag, encryption, archive, or embedded-file indicators were detected."
            )
        return explanation
