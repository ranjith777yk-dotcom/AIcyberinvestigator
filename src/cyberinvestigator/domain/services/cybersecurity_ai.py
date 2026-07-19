"""Fallback-safe cybersecurity investigation assistant and analysis engine."""

from __future__ import annotations

import base64
import binascii
import email
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|ir|kp|info|biz|xyz)\b", re.I
    ),
    "url": re.compile(r"\bhttps?://[^\s<>'\"]+", re.I),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

MITRE_RULES = {
    "powershell": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
    "rundll32": ("T1218.011", "Rundll32"),
    "regsvr32": ("T1218.010", "Regsvr32"),
    "credential": ("T1003", "OS Credential Dumping"),
    "mimikatz": ("T1003.001", "LSASS Memory"),
    "scheduled task": ("T1053.005", "Scheduled Task"),
    "encodedcommand": ("T1027", "Obfuscated Files or Information"),
    "phishing": ("T1566", "Phishing"),
    "macro": ("T1204.002", "Malicious File"),
    "exfil": ("T1041", "Exfiltration Over C2 Channel"),
}

SUSPICIOUS_TERMS = {
    "mimikatz": 30,
    "ransom": 25,
    "encodedcommand": 20,
    "powershell": 12,
    "credential": 18,
    "beacon": 18,
    "c2": 18,
    "exfil": 20,
    "phishing": 12,
    "malware": 15,
}


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Serializable investigation analysis output."""

    summary: str
    iocs: dict[str, list[str]]
    mitre_attack: list[dict[str, str]]
    file_metadata: dict[str, object]
    hashes: dict[str, str]
    yara: list[dict[str, str]]
    sigma: list[dict[str, str]]
    threat_intel: dict[str, object]
    email_headers: dict[str, object]
    log_findings: list[dict[str, object]]
    ocr: dict[str, object]
    pdf: dict[str, object]
    image_metadata: dict[str, object]
    correlations: list[str]
    threat_score: int
    recommendations: list[str]
    provider_status: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "iocs": self.iocs,
            "mitre_attack": self.mitre_attack,
            "file_metadata": self.file_metadata,
            "hashes": self.hashes,
            "yara": self.yara,
            "sigma": self.sigma,
            "threat_intel": self.threat_intel,
            "email_headers": self.email_headers,
            "log_findings": self.log_findings,
            "ocr": self.ocr,
            "pdf": self.pdf,
            "image_metadata": self.image_metadata,
            "correlations": self.correlations,
            "threat_score": self.threat_score,
            "recommendations": self.recommendations,
            "provider_status": self.provider_status,
        }


class ConversationMemoryStore:
    """Simple process-local conversation memory keyed by case."""

    def __init__(self) -> None:
        self._items: dict[str, list[dict[str, str]]] = {}

    def append(self, case_id: str, role: str, content: str) -> None:
        self._items.setdefault(case_id, []).append({"role": role, "content": content})
        self._items[case_id] = self._items[case_id][-40:]

    def list(self, case_id: str) -> list[dict[str, str]]:
        return list(self._items.get(case_id, ()))


class CybersecurityAnalysisEngine:
    """Deterministic analyzer covering local cybersecurity capabilities."""

    def analyze_text(self, text: str, *, filename: str | None = None) -> AnalysisResult:
        text = text or ""
        lowered = text.lower()
        iocs = {name: sorted(set(pattern.findall(text))) for name, pattern in IOC_PATTERNS.items()}
        mitre = [
            {"technique_id": tid, "technique": name, "matched": marker}
            for marker, (tid, name) in MITRE_RULES.items()
            if marker in lowered
        ]
        sigma = self._sigma_findings(lowered)
        yara = self._yara_findings(text)
        log_findings = self._log_findings(text)
        email_headers = self._email_headers(text)
        score = self._score(text, iocs, mitre, sigma, yara, log_findings)
        recommendations = self._recommendations(score, iocs, mitre, email_headers)
        summary = self._summary(score, iocs, mitre, filename)
        return AnalysisResult(
            summary=summary,
            iocs=iocs,
            mitre_attack=mitre,
            file_metadata={"filename": filename, "text_length": len(text), "line_count": len(text.splitlines())},
            hashes={},
            yara=yara,
            sigma=sigma,
            threat_intel=self._threat_intel(iocs),
            email_headers=email_headers,
            log_findings=log_findings,
            ocr={
                "available": False,
                "text": "",
                "message": "OCR requires an optional OCR backend; local fallback preserved.",
            },
            pdf={
                "available": False,
                "text": "",
                "message": "PDF text extraction uses optional libraries when installed.",
            },
            image_metadata={
                "available": False,
                "metadata": {},
                "message": "Image metadata extraction uses optional imaging libraries when installed.",
            },
            correlations=self._correlations(iocs, mitre),
            threat_score=score,
            recommendations=recommendations,
        )

    def analyze_file(self, path: Path) -> AnalysisResult:
        data = path.read_bytes()
        text = self._decode_text(data)
        result = self.analyze_text(text, filename=path.name)
        hashes = {
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        metadata = dict(result.file_metadata)
        metadata.update({"size_bytes": len(data), "suffix": path.suffix.lower()})
        pdf = self._pdf_metadata(data, path)
        image = self._image_metadata(data, path)
        return AnalysisResult(
            **{**result.as_dict(), "hashes": hashes, "file_metadata": metadata, "pdf": pdf, "image_metadata": image}
        )

    def _decode_text(self, data: bytes) -> str:
        for encoding in ("utf-8", "utf-16", "latin-1"):
            try:
                return data.decode(encoding, errors="ignore")
            except LookupError:
                continue
        return ""

    def _score(
        self,
        text: str,
        iocs: dict[str, list[str]],
        mitre: list[dict[str, str]],
        sigma: list[dict[str, str]],
        yara: list[dict[str, str]],
        logs: list[dict[str, object]],
    ) -> int:
        lowered = text.lower()
        score = sum(weight for term, weight in SUSPICIOUS_TERMS.items() if term in lowered)
        score += min(25, sum(len(values) for values in iocs.values()) * 3)
        score += len(mitre) * 8 + len(sigma) * 10 + len(yara) * 10 + len(logs) * 4
        return max(0, min(100, score))

    def _summary(
        self, score: int, iocs: dict[str, list[str]], mitre: list[dict[str, str]], filename: str | None
    ) -> str:
        ioc_count = sum(len(values) for values in iocs.values())
        target = f" for {filename}" if filename else ""
        return f"Local analysis{target} found {ioc_count} IOC(s), {len(mitre)} ATT&CK mapping(s), and a threat score of {score}/100."

    def _recommendations(
        self, score: int, iocs: dict[str, list[str]], mitre: list[dict[str, str]], headers: dict[str, object]
    ) -> list[str]:
        items = ["Preserve original evidence and document chain of custody."]
        if score >= 60:
            items.append("Escalate for containment review and priority triage.")
        if any(iocs.get(key) for key in ("ipv4", "domain", "url")):
            items.append("Enrich network IOCs with approved threat intelligence sources.")
        if mitre:
            items.append("Validate mapped ATT&CK techniques against endpoint and timeline evidence.")
        if headers:
            items.append("Review SPF/DKIM/DMARC alignment and received-chain anomalies.")
        return items

    def _threat_intel(self, iocs: dict[str, list[str]]) -> dict[str, object]:
        indicators = sum(len(values) for values in iocs.values())
        return {
            "available": False,
            "indicator_count": indicators,
            "message": "External threat intelligence is disabled unless an API key/provider is configured.",
        }

    def _email_headers(self, text: str) -> dict[str, object]:
        if "received:" not in text.lower() and "from:" not in text.lower():
            return {}
        message = email.message_from_string(text)
        received = message.get_all("Received", [])
        return {
            "from": message.get("From"),
            "to": message.get("To"),
            "subject": message.get("Subject"),
            "received_hops": len(received),
            "authentication_results": message.get_all("Authentication-Results", []),
            "suspicious": len(received) == 0
            or "fail" in " ".join(message.get_all("Authentication-Results", [])).lower(),
        }

    def _log_findings(self, text: str) -> list[dict[str, object]]:
        findings = []
        for index, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            if any(term in lowered for term in ("error", "failed", "denied", "malware", "powershell", "mimikatz")):
                findings.append(
                    {"line": index, "severity": "high" if "mimikatz" in lowered else "medium", "message": line[:300]}
                )
        return findings[:50]

    def _sigma_findings(self, lowered: str) -> list[dict[str, str]]:
        rules = []
        if "powershell" in lowered and ("-enc" in lowered or "encodedcommand" in lowered):
            rules.append({"rule": "proc_creation_win_powershell_encoded_command", "severity": "high"})
        if "rundll32" in lowered and "http" in lowered:
            rules.append({"rule": "proc_creation_win_rundll32_network_execution", "severity": "high"})
        return rules

    def _yara_findings(self, text: str) -> list[dict[str, str]]:
        findings = []
        if "MZ" in text[:256]:
            findings.append({"rule": "pe_header_present", "severity": "medium"})
        if re.search(r"[A-Za-z0-9+/]{80,}={0,2}", text):
            findings.append({"rule": "long_base64_blob", "severity": "medium"})
        return findings

    def _pdf_metadata(self, data: bytes, path: Path) -> dict[str, object]:
        if path.suffix.lower() != ".pdf" and not data.startswith(b"%PDF"):
            return {"available": False, "metadata": {}}
        return {
            "available": True,
            "metadata": {"header": data[:8].decode("latin-1", errors="ignore"), "xref_markers": data.count(b"xref")},
            "text": "",
        }

    def _image_metadata(self, data: bytes, path: Path) -> dict[str, object]:
        suffix = path.suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff"}:
            return {"available": False, "metadata": {}}
        metadata: dict[str, object] = {"suffix": suffix, "size_bytes": len(data)}
        if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
            metadata["format"] = "png"
            metadata["width"] = int.from_bytes(data[16:20], "big")
            metadata["height"] = int.from_bytes(data[20:24], "big")
        elif data.startswith(b"\xff\xd8"):
            metadata["format"] = "jpeg"
        return {"available": True, "metadata": metadata}

    def _correlations(self, iocs: dict[str, list[str]], mitre: list[dict[str, str]]) -> list[str]:
        correlations = []
        domains = set(iocs.get("domain", []))
        urls = iocs.get("url", [])
        overlap = [url for url in urls if any(domain in url for domain in domains)]
        if overlap:
            correlations.append(f"{len(overlap)} URL(s) correlate with extracted domains.")
        counts = Counter(item["technique_id"] for item in mitre)
        correlations.extend(f"Technique {technique} matched {count} signal(s)." for technique, count in counts.items())
        return correlations


class InvestigationAssistant:
    """Case-aware, evidence-aware, timeline-aware assistant facade."""

    def __init__(self, analyzer: CybersecurityAnalysisEngine, memory: ConversationMemoryStore) -> None:
        self.analyzer = analyzer
        self.memory = memory

    def respond(
        self,
        *,
        message: str,
        case_context: dict[str, object],
        provider_reply: str | None = None,
        provider_status: dict[str, object] | None = None,
    ) -> dict[str, object]:
        case_id = str(case_context.get("case_id") or "workspace")
        self.memory.append(case_id, "user", message)
        text = "\n".join([message, json.dumps(case_context, default=str)])
        analysis = self.analyzer.analyze_text(text)
        reply = provider_reply or self._local_reply(message, case_context, analysis)
        self.memory.append(case_id, "assistant", reply)
        payload = analysis.as_dict()
        payload["provider_status"] = provider_status or {}
        return {"reply": reply, "analysis": payload, "memory": self.memory.list(case_id)}

    def _local_reply(self, message: str, context: dict[str, object], analysis: AnalysisResult) -> str:
        case_label = context.get("case_number") or context.get("case_id") or "the current workspace"
        lower = message.lower().strip()
        evidence = context.get("evidence", []) if isinstance(context.get("evidence"), list) else []
        timeline = context.get("timeline", []) if isinstance(context.get("timeline"), list) else []
        reports = context.get("reports", []) if isinstance(context.get("reports"), list) else []
        uploads = context.get("uploaded_evidence", []) if isinstance(context.get("uploaded_evidence"), list) else []

        if lower in {"hi", "hello", "hey", "good morning", "good afternoon", "good evening"}:
            return "Hello! Welcome back to AI Cyber Investigator.\n\n" "How can I help you today?"

        if lower in {"good night", "goodnight"}:
            return "Good night. I will be ready when you come back to continue the investigation."

        if lower in {"how are you", "how are you?", "how's it going", "how is it going"}:
            return (
                "I am doing well and ready to help.\n\n"
                "I can explain cybersecurity concepts, review evidence, summarize the current investigation, map "
                "findings to MITRE ATT&CK, decode suspicious content, or draft a forensic report."
            )

        if lower in {"thanks", "thank you", "thank you!", "thanks!"}:
            return "You are welcome. Send the next artifact, question, or investigation task whenever you are ready."

        if "what is sql injection" in lower:
            lower = "sql injection"

        if "explain this malware" in lower or "analyze malware" in lower or "malware" in lower:
            return (
                "I can help explain the malware behavior. Share the sample notes, hashes, strings, process activity, "
                "network indicators, or uploaded evidence and I will break down likely capability, persistence, C2, "
                "defense-evasion signals, and recommended containment steps."
            )

        if "phishing" in lower:
            return (
                "Phishing is a social-engineering attack that attempts to trick a user into revealing credentials, "
                "opening a malicious attachment, approving a fake login, or visiting a controlled site.\n\n"
                "Key indicators include spoofed sender domains, urgent language, mismatched links, suspicious "
                "attachments, unusual authentication prompts, and newly registered infrastructure. Validate headers, "
                "URLs, attachment hashes, mailbox rules, sign-in logs, and any downstream account activity."
            )

        if "ransomware" in lower:
            return (
                "Ransomware is malware that disrupts availability by encrypting data, deleting backups, or threatening "
                "data exposure for extortion.\n\n"
                "A professional triage should identify initial access, lateral movement, privilege escalation, "
                "encryption scope, impacted identities, backup integrity, exfiltration evidence, and recovery options. "
                "Preserve volatile evidence before containment whenever operationally safe."
            )

        if "logs" in lower or "explain log" in lower:
            return (
                "I can explain logs by correlating timestamp, source, actor, action, target, result, and surrounding "
                "events.\n\n"
                "For security review, focus on failed-to-successful login sequences, impossible travel, privilege "
                "changes, process creation, PowerShell/script execution, DNS or HTTP beacons, blocked controls, and "
                "events that align with known MITRE ATT&CK techniques."
            )

        if "memory dump" in lower or "memory image" in lower:
            return (
                "For a memory dump, I would triage running processes, parent-child relationships, injected memory, "
                "network sockets, loaded modules, command-line arguments, handles, registry artifacts, credentials "
                "risk, and persistence clues.\n\n"
                "Upload the dump or share extracted process/network artifacts and I will summarize suspicious "
                "behavior, likely tactics, and the next validation steps."
            )

        if "pcap" in lower or "packet capture" in lower:
            return (
                "For a PCAP, I would review conversations, DNS queries, HTTP hosts, TLS SNI, unusual ports, beaconing "
                "patterns, file transfers, authentication attempts, and extracted objects.\n\n"
                "Useful outputs include IOCs, suspected C2 infrastructure, timeline of network activity, protocol "
                "anomalies, and MITRE mappings for command-and-control or exfiltration behavior."
            )

        if "zip" in lower or "archive" in lower:
            return (
                "For a ZIP or archive, I would verify magic bytes, compression method, encryption flags, nested "
                "archives, file paths, timestamps, hidden files, metadata, high-entropy content, embedded scripts, "
                "and printable strings.\n\n"
                "If you upload it, I can analyze extracted contents recursively and preserve the chain of custody."
            )

        decoded = self._decode_if_requested(message)
        if decoded:
            return decoded

        if "sql injection" in lower or "sqli" in lower:
            return (
                "SQL Injection is a web application vulnerability where untrusted input is inserted into a SQL query "
                "without safe parameterization.\n\n"
                "An attacker may use it to bypass authentication, read sensitive data, modify records, or execute "
                "database-specific actions. Common signs include payloads such as `' OR '1'='1`, stacked queries, "
                "UNION-based extraction, time delays, and database error leakage.\n\n"
                "Defenses: use parameterized queries, avoid string-built SQL, validate input, apply least-privilege "
                "database accounts, suppress detailed database errors, monitor unusual query patterns, and add WAF "
                "rules as defense in depth."
            )

        if any(term in lower for term in ("forensic report", "generate report", "report draft")):
            return (
                f"## Forensic Report Draft\n\n"
                f"### Executive Summary\n{case_label} contains {len(evidence)} evidence item(s), "
                f"{len(timeline)} timeline event(s), and {len(reports)} generated report(s).\n\n"
                f"### Findings\n{analysis.summary}\n\n"
                f"### Threat Score\n{analysis.threat_score}/100\n\n"
                "### Recommendations\n"
                + "\n".join(f"- {item}" for item in analysis.recommendations)
                + "\n\n### Chain of Custody\nEvidence hashes, acquisition timestamps, and analysis reports should be preserved "
                "before sharing or exporting."
            )

        if "ioc" in lower:
            iocs = analysis.iocs
            if not any(iocs.values()):
                return (
                    "I do not see a strong IOC in the current message or case context. Send the domain, IP, URL, hash, "
                    "email address, or filename you want explained, and I will classify it, describe risk, and suggest "
                    "safe validation steps."
                )
            lines = ["## IOC Explanation"]
            for kind, values in iocs.items():
                for value in values[:8]:
                    lines.append(
                        f"- **{kind.upper()}** `{value}`: validate reputation, source context, and related events."
                    )
            return "\n".join(lines)

        if "recommendation" in lower or "recommendations" in lower:
            return "## Recommendations\n" + "\n".join(f"- {item}" for item in analysis.recommendations)

        if "mitre" in lower or "attack" in lower:
            if not analysis.mitre_attack:
                return (
                    "I do not have enough concrete behavior to map a precise MITRE ATT&CK technique yet. Share process, "
                    "network, authentication, or persistence details and I will map tactics, techniques, and rationale."
                )
            return "## MITRE ATT&CK Mapping\n" + "\n".join(
                f"- **{item.get('technique_id', 'Unknown')} {item.get('technique', 'Technique')}**: "
                f"matched `{item.get('matched', 'case context')}`"
                for item in analysis.mitre_attack
            )

        if any(term in lower for term in ("evidence", "summarize evidence", "uploaded", "explain this")):
            if uploads:
                return (
                    f"I registered and analyzed {len(uploads)} uploaded item(s). "
                    f"Current case context now includes {len(evidence)} evidence item(s). "
                    f"Local findings: {analysis.summary}\n\n"
                    "Recommended next steps: review extracted strings, confirm hashes, inspect high-entropy regions, "
                    "and correlate findings with the timeline."
                )
            return (
                f"{case_label} currently has {len(evidence)} evidence item(s). {analysis.summary} "
                "Ask me about a specific file, hash, string, archive, or IOC and I will drill into it."
            )

        if any(term in lower for term in ("summarize", "summary", "investigation")):
            return (
                f"## Investigation Summary\n\n"
                f"- **Case:** {case_label}\n"
                f"- **Evidence items:** {len(evidence)}\n"
                f"- **Timeline events:** {len(timeline)}\n"
                f"- **Reports:** {len(reports)}\n"
                f"- **Threat score:** {analysis.threat_score}/100\n\n"
                f"{analysis.summary}\n\n"
                "Recommended next action: "
                f"{analysis.recommendations[-1]}"
            )

        return (
            f"I can help with that. From the current context for {case_label}, I see {len(evidence)} evidence item(s), "
            f"{len(timeline)} timeline event(s), and a local threat score of {analysis.threat_score}/100.\n\n"
            f"{analysis.summary}\n\n"
            "Tell me whether you want a concise answer, deep forensic analysis, MITRE mapping, IOC explanation, or a "
            "report-ready write-up."
        )

    @staticmethod
    def _decode_if_requested(message: str) -> str | None:
        lower = message.lower()
        if "base64" not in lower and "decode" not in lower:
            return None
        candidates = [part.strip("`'\" \n\r\t") for part in message.replace(":", " ").split()]
        for candidate in candidates:
            if len(candidate) < 8:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True)
                preview = decoded[:2000].decode("utf-8", errors="replace")
                return f"Decoded Base64 content:\n\n```text\n{preview}\n```"
            except (binascii.Error, ValueError):
                continue
        return "I can decode Base64. Paste the encoded value or attach a file, and I will decode it safely."
