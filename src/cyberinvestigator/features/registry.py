"""Central feature registry wired by the application composition root."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from flask import Flask

from cyberinvestigator.features.ai import AIFeature
from cyberinvestigator.features.cases import CaseFeature
from cyberinvestigator.features.evidence import EvidenceFeature
from cyberinvestigator.features.threat_intelligence import ThreatIntelligenceFeature
from cyberinvestigator.features.timeline import TimelineFeature
from cyberinvestigator.infrastructure.evidence_storage import EvidenceFileLocator, LocalEvidenceStorage


@dataclass(frozen=True, slots=True)
class FeatureRegistry:
    """Configured business capabilities available to transport adapters."""

    cases: CaseFeature
    evidence: EvidenceFeature
    timeline: TimelineFeature
    ai: AIFeature
    threat_intelligence: ThreatIntelligenceFeature


def register_feature_modules(app: Flask) -> FeatureRegistry:
    """Wire feature capabilities once while preserving legacy extension keys."""
    ai_registry = app.extensions["cyberinvestigator_ai_registry"]
    quarantine_root = Path(app.config["QUARANTINE_UPLOAD_FOLDER"])
    incoming_root = Path(app.config["UPLOAD_FOLDER"])
    max_evidence_bytes = int(app.config.get("EVIDENCE_MAX_FILE_BYTES") or app.config["MAX_CONTENT_LENGTH"])
    features = FeatureRegistry(
        cases=CaseFeature(),
        evidence=EvidenceFeature(
            LocalEvidenceStorage(quarantine_root, max_bytes=max_evidence_bytes),
            EvidenceFileLocator(quarantine_root, (incoming_root,)),
        ),
        timeline=TimelineFeature(),
        ai=AIFeature(ai_registry),
        threat_intelligence=ThreatIntelligenceFeature(
            tuple(app.extensions.get("cyberinvestigator_threat_intelligence_providers", ()))
        ),
    )
    app.extensions["cyberinvestigator_features"] = features
    app.extensions["cyberinvestigator"]["features"] = features
    return features
