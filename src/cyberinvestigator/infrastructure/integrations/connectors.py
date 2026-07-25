"""Provider-neutral contracts for third-party security connectors."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol


class ConnectorCategory(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    THREAT_INTELLIGENCE = "threat_intelligence"
    TICKETING = "ticketing"
    STORAGE = "storage"
    MESSAGING = "messaging"
    IDENTITY = "identity"
    CUSTOM = "custom"


class ConnectorHealthState(str, Enum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorHealth:
    state: ConnectorHealthState
    message: str
    checked_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectorSyncResult:
    status: str
    records_processed: int
    message: str
    completed_at: str
    cursor: str | None = None


class EnterpriseConnector(Protocol):
    """Optional runtime contract implemented by integration-oriented plugins."""

    def health(
        self,
        *,
        configuration: Mapping[str, object],
        credentials: Mapping[str, str],
    ) -> ConnectorHealth: ...

    def synchronize(
        self,
        *,
        configuration: Mapping[str, object],
        credentials: Mapping[str, str],
        cursor: str | None,
    ) -> ConnectorSyncResult: ...
