"""Deterministic forensic file analysis for evidence triage."""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
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
from typing import Callable, Final


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
    _URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>]+", re.I)
    _DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.I)
    _IP_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
    _SUSPICIOUS_COMMANDS: Final[tuple[str, ...]] = (
        "powershell -enc",
        "invoke-expression",
        "certutil -decode",
        "curl http",
        "wget http",
        "cmd.exe /c",
        "rundll32",
        "regsvr32",
        "mshta",
        "chmod +x",
        "/bin/sh -c",
    )
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
        self,
        path: Path,
        *,
        evidence_number: str,
        original_filename: str,
        sha256: str,
        progress: Callable[[int, str], None] | None = None,
    ) -> ForensicAnalysisResult:
        """Analyze one stored evidence file and return a full report."""
        notify = progress or (lambda _value, _step: None)
        notify(22, "Hashing and verifying custody metadata")
        digest = hashlib.sha256()
        captured = bytearray()
        size_bytes = 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size_bytes += len(chunk)
                if len(captured) < self.MAX_BYTES:
                    captured.extend(chunk[: self.MAX_BYTES - len(captured)])
        if digest.hexdigest() != sha256:
            raise ValueError("Evidence integrity verification failed; stored bytes do not match the custody hash.")
        data = bytes(captured)
        truncated = size_bytes > len(data)
        notify(32, "Detecting archives and embedded files")
        root = self._analyze_bytes(data, original_filename, depth=0)
        notify(48, "Extracting strings and finding encodings")
        findings = self._flatten_findings(root)
        notify(58, "Finding encryption and hidden content")
        iocs = self._collect_iocs(root)
        notify(66, "Running YARA indicators")
        yara_results = self._yara_matches(root)
        notify(72, "Running Sigma indicators")
        sigma_results = self._sigma_matches(root)
        notify(78, "Extracting IOCs and MITRE ATT&CK mappings")
        mitre = self._mitre_mapping(root, yara_results, sigma_results)
        risk_score = min(100, 10 + len(findings) * 8 + len(yara_results) * 15 + len(sigma_results) * 12)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": self._executive_summary(findings, root),
            "evidence": {
                "evidence_number": evidence_number,
                "original_filename": original_filename,
                "stored_path": str(path),
                "sha256": sha256,
                "integrity_verified": True,
                "stored_size_bytes": size_bytes,
                "bytes_analyzed": len(data),
                "truncated": truncated,
            },
            "threat_assessment": self._threat_assessment(findings, root),
            "technical_summary": self._summary(findings, root),
            "evidence_summary": {
                "signature": root.get("file_signature"),
                "entropy": root.get("entropy"),
                "size_bytes": root.get("size_bytes"),
            },
            "recovered_files": self._recovered_files(root),
            "chain_of_custody": [
                "Evidence bytes were read from quarantine custody storage without execution.",
                "The full stored object was rehashed and matched the persisted SHA-256 custody value.",
                "Analysis was read-only; extracted children were analyzed in memory.",
            ],
            "root": root,
            "findings": findings,
            "forensic_findings": self._enterprise_findings(findings),
            "recovered_artifacts": self._recovered_artifacts(findings, evidence_number),
            "confidence_score": self._confidence_score(findings, root),
            "risk_score": risk_score,
            "ioc_table": iocs,
            "mitre_mapping": mitre,
            "yara_results": yara_results,
            "sigma_results": sigma_results,
            "timeline_summary": "Analysis completion is recorded in the investigation timeline with evidence provenance.",
            "recommendations": self._recommendations(findings),
            "explanation": self._explain(findings, root),
            "appendix": {
                "analysis_limits": {
                    "max_bytes": self.MAX_BYTES,
                    "max_depth": self.MAX_DEPTH,
                    "max_children": self.MAX_CHILDREN,
                }
            },
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
            "suspicious_commands": [
                value for value in strings if any(command in value.lower() for command in self._SUSPICIOUS_COMMANDS)
            ][:25],
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
                        with archive.open(info, pwd=None) as member:
                            child = member.read(self.MAX_BYTES)
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
        for label in ("gzip", "bzip2", "xz", "zlib"):
            try:
                expanded = self._bounded_decompress(data, label)
            except (OSError, EOFError, lzma.LZMAError, zlib.error):
                continue
            children.append(self._analyze_bytes(expanded, f"{name}.{label}.decompressed", depth=depth + 1))
            break
        return children

    def _bounded_decompress(self, data: bytes, algorithm: str) -> bytes:
        """Expand at most MAX_BYTES so compressed evidence cannot exhaust memory."""

        if algorithm == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                return stream.read(self.MAX_BYTES)
        if algorithm == "bzip2":
            with bz2.BZ2File(io.BytesIO(data)) as stream:
                return stream.read(self.MAX_BYTES)
        if algorithm == "xz":
            with lzma.LZMAFile(io.BytesIO(data)) as stream:
                return stream.read(self.MAX_BYTES)
        return zlib.decompressobj().decompress(data, self.MAX_BYTES)

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

    def _walk_nodes(self, root: dict[str, object]):
        yield root
        for child in root.get("children", []):
            if isinstance(child, dict) and "error" not in child:
                yield from self._walk_nodes(child)

    def _collect_iocs(self, root: dict[str, object]) -> list[dict[str, str]]:
        found: set[tuple[str, str]] = set()
        for node in self._walk_nodes(root):
            text = "\n".join(str(item) for item in node.get("hidden_strings", []))
            for kind, pattern in (
                ("URL", self._URL_PATTERN),
                ("Domain", self._DOMAIN_PATTERN),
                ("IP", self._IP_PATTERN),
                ("Email", self._EMAIL_PATTERN),
            ):
                for value in pattern.findall(text):
                    if kind == "IP" and any(int(part) > 255 for part in value.split(".")):
                        continue
                    found.add((kind, value))
        return [
            {"type": kind, "value": value, "confidence": "high", "source": "extracted strings"}
            for kind, value in sorted(found)
        ][:200]

    def _yara_matches(self, root: dict[str, object]) -> list[dict[str, object]]:
        matches = []
        for node in self._walk_nodes(root):
            joined = " ".join(str(item).lower() for item in node.get("hidden_strings", []))
            signature = str(node.get("file_signature", ""))
            rules = (
                ("Suspicious_PowerShell", ("powershell -enc", "invoke-expression")),
                ("Credential_Access_Strings", ("mimikatz", "sekurlsa", "lsass")),
                ("Webshell_Indicators", ("eval($_post", "cmd.exe /c", "system($_get")),
            )
            for rule, needles in rules:
                hits = [needle for needle in needles if needle in joined]
                if hits:
                    matches.append({"rule": rule, "location": node.get("name"), "matches": hits, "confidence": 0.82})
            if signature in {"Windows PE executable", "ELF executable"} and float(node.get("entropy", 0)) > 7.3:
                matches.append(
                    {
                        "rule": "High_Entropy_Executable",
                        "location": node.get("name"),
                        "matches": ["entropy"],
                        "confidence": 0.7,
                    }
                )
        return matches

    def _sigma_matches(self, root: dict[str, object]) -> list[dict[str, object]]:
        results = []
        for node in self._walk_nodes(root):
            for command in node.get("suspicious_commands", []):
                results.append(
                    {
                        "rule": "Suspicious command execution",
                        "location": node.get("name"),
                        "evidence": command,
                        "confidence": 0.76,
                    }
                )
        return results[:100]

    @staticmethod
    def _mitre_mapping(
        root: dict[str, object], yara: list[dict[str, object]], sigma: list[dict[str, object]]
    ) -> list[dict[str, str]]:
        text = " ".join(str(item).lower() for item in root.get("hidden_strings", []))
        mappings = []
        if "powershell" in text or any("PowerShell" in str(item.get("rule")) for item in yara):
            mappings.append(
                {
                    "technique_id": "T1059.001",
                    "technique": "PowerShell",
                    "reason": "PowerShell execution indicators were recovered.",
                }
            )
        if "mimikatz" in text or "lsass" in text:
            mappings.append(
                {
                    "technique_id": "T1003",
                    "technique": "OS Credential Dumping",
                    "reason": "Credential access strings were recovered.",
                }
            )
        if sigma:
            mappings.append(
                {
                    "technique_id": "T1059",
                    "technique": "Command and Scripting Interpreter",
                    "reason": "Suspicious command strings were recovered.",
                }
            )
        return mappings

    def _recovered_files(self, root: dict[str, object]) -> list[dict[str, object]]:
        return [
            {"name": node.get("name"), "signature": node.get("file_signature"), "size_bytes": node.get("size_bytes")}
            for node in self._walk_nodes(root)
            if node is not root
        ]

    @staticmethod
    def _enterprise_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
        enriched = []
        for item in findings:
            finding_type = str(item.get("type", "finding"))
            severity = str(item.get("severity", "info"))
            detail = str(item.get("detail", ""))
            path = str(item.get("path", "root"))
            if finding_type == "ctf_flag":
                title = "Recovered Artifact"
                reason = "The value matched a known CTF flag pattern in extracted strings or decoded payloads."
                action = "Validate the artifact against challenge scope and preserve the extraction path."
                confidence = 0.92
            elif "encryption" in finding_type:
                title = "Encryption or Packed-Content Indicator"
                reason = "Entropy, metadata, or archive flags indicate encrypted, compressed, or packed content."
                action = "Confirm with alternate tooling and preserve the original bytes before attempting recovery."
                confidence = 0.74
            elif "steganography" in finding_type:
                title = "Potential Steganography Indicator"
                reason = "Trailing bytes or known tool markers suggest hidden content may be present."
                action = "Review with approved steganography tools and document every extracted artifact."
                confidence = 0.68
            elif "embedded" in finding_type:
                title = "Embedded File Indicator"
                reason = "A secondary file signature was found inside the analyzed byte stream."
                action = "Extract the embedded object in a controlled environment and analyze it as child evidence."
                confidence = 0.8
            else:
                title = finding_type.replace("_", " ").title()
                reason = "The local forensic parser identified this property during read-only triage."
                action = "Correlate with the case timeline and validate relevance before escalation."
                confidence = 0.6 if severity == "info" else 0.72
            enriched.append(
                {
                    "title": title,
                    "description": detail,
                    "reason": reason,
                    "confidence": confidence,
                    "severity": severity,
                    "location": path,
                    "recommended_action": action,
                }
            )
        return enriched

    @staticmethod
    def _recovered_artifacts(findings: list[dict[str, object]], evidence_number: str) -> list[dict[str, object]]:
        artifacts = []
        for item in findings:
            if item.get("type") != "ctf_flag":
                continue
            artifacts.append(
                {
                    "title": "Recovered Artifact",
                    "artifact": item.get("detail"),
                    "location": item.get("path"),
                    "confidence": 0.92,
                    "validation": "Matched flag-like syntax during string and decoded-payload analysis.",
                    "why_identified": "Pattern matched known flag conventions and was recovered from evidence bytes.",
                    "evidence_path": f"{evidence_number}:{item.get('path')}",
                    "associated_files": [item.get("path")],
                    "technical_explanation": "The analyzer searched printable strings and decoded payload previews, then recorded the path where the artifact was observed.",
                }
            )
        return artifacts

    @staticmethod
    def _confidence_score(findings: list[dict[str, object]], root: dict[str, object]) -> int:
        score = 55
        if root.get("file_signature") != "Unknown":
            score += 10
        if findings:
            score += min(25, len(findings) * 4)
        if any(item.get("type") == "ctf_flag" for item in findings):
            score += 10
        return min(98, score)

    @staticmethod
    def _threat_assessment(findings: list[dict[str, object]], root: dict[str, object]) -> dict[str, object]:
        high = sum(1 for item in findings if item.get("severity") == "high")
        medium = sum(1 for item in findings if item.get("severity") == "medium")
        severity = "high" if high else "medium" if medium else "low"
        return {
            "severity": severity,
            "reason": f"{high} high and {medium} medium confidence forensic indicator(s) were identified.",
            "entropy": root.get("entropy"),
            "signature": root.get("file_signature"),
        }

    @staticmethod
    def _recommendations(findings: list[dict[str, object]]) -> list[str]:
        items = ["Preserve the original evidence and retain hash verification in the case record."]
        if any(item.get("type") == "ctf_flag" for item in findings):
            items.append("Validate recovered artifacts against the challenge or investigation scope before reporting.")
        if any("embedded" in str(item.get("type")) for item in findings):
            items.append("Extract embedded objects as child evidence and analyze them independently.")
        if any("encryption" in str(item.get("type")) for item in findings):
            items.append(
                "Use approved recovery workflows for encrypted or packed content; avoid destructive modification."
            )
        return items

    @staticmethod
    def _executive_summary(findings: list[dict[str, object]], root: dict[str, object]) -> str:
        return (
            f"Read-only forensic triage identified {len(findings)} notable indicator(s) in a "
            f"{root.get('file_signature', 'Unknown')} artifact with entropy {root.get('entropy', '-')}. "
            "The report includes evidence context, recovered artifacts, confidence scoring, and recommended actions."
        )

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
