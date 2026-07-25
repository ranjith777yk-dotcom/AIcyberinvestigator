"""Provider-neutral contracts for traceable threat-intelligence enrichment."""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IndicatorReputation(str, Enum):
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True, slots=True)
class NormalizedIndicator:
    type: IndicatorType
    value: str
    original_value: str


@dataclass(frozen=True, slots=True)
class IntelligenceFinding:
    """One provider assertion. Confidence never substitutes for reputation."""

    provider: str
    indicator: NormalizedIndicator
    reputation: IndicatorReputation
    confidence: float | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reference: str | None = None
    summary: str | None = None
    attack_techniques: tuple[str, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)


class ThreatIntelligenceProvider(ABC):
    """Adapter boundary responsible for credentials, transport, and response parsing."""

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @abstractmethod
    def supports(self, indicator_type: IndicatorType) -> bool: ...

    @abstractmethod
    def enrich(self, indicator: NormalizedIndicator) -> IntelligenceFinding | None: ...


def normalize_indicator(indicator_type: str, value: str) -> NormalizedIndicator:
    """Return a canonical value or raise ValueError for malformed input."""
    original = value.strip()
    kind = IndicatorType(indicator_type.strip().lower())
    normalized = original
    if kind in {IndicatorType.IPV4, IndicatorType.IPV6}:
        address = ipaddress.ip_address(original)
        if (kind is IndicatorType.IPV4) != (address.version == 4):
            raise ValueError("Indicator type does not match the IP address version.")
        normalized = address.compressed
    elif kind is IndicatorType.DOMAIN:
        normalized = original.rstrip(".").lower().encode("idna").decode("ascii")
        if not normalized or "." not in normalized or any(not label for label in normalized.split(".")):
            raise ValueError("Domain indicator is malformed.")
    elif kind is IndicatorType.URL:
        parsed = urlsplit(original)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL indicator must use HTTP or HTTPS and include a host.")
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        port = f":{parsed.port}" if parsed.port else ""
        normalized = urlunsplit((parsed.scheme.lower(), host + port, parsed.path or "/", parsed.query, ""))
    elif kind is IndicatorType.EMAIL:
        local, separator, domain = original.rpartition("@")
        if not separator or not local or "." not in domain:
            raise ValueError("Email indicator is malformed.")
        normalized = f"{local}@{domain.rstrip('.').lower().encode('idna').decode('ascii')}"
    else:
        expected = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}[kind]
        normalized = original.lower()
        if len(normalized) != expected or any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError(f"{kind.value.upper()} indicator is malformed.")
    return NormalizedIndicator(kind, normalized, original)
