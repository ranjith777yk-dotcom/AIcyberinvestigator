"""Threat-intelligence feature composition boundary."""

from cyberinvestigator.application.ports.threat_intelligence import ThreatIntelligenceProvider
from cyberinvestigator.domain.services.threat_intelligence import ThreatIntelligenceCorrelationEngine


class ThreatIntelligenceFeature:
    def __init__(self, providers: tuple[ThreatIntelligenceProvider, ...] = ()) -> None:
        self._engine = ThreatIntelligenceCorrelationEngine(providers)

    @property
    def engine(self) -> ThreatIntelligenceCorrelationEngine:
        return self._engine
