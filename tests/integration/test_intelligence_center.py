from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.application.ports.threat_intelligence import (
    IndicatorReputation,
    IndicatorType,
    IntelligenceFinding,
    NormalizedIndicator,
    ThreatIntelligenceProvider,
)
from cyberinvestigator.domain.services.threat_intelligence import ThreatIntelligenceCorrelationEngine
from cyberinvestigator.infrastructure.database.migrations import DEFAULT_ORGANIZATION_ID
from cyberinvestigator.infrastructure.database.models import (
    AuditLog,
    IntelligenceIndicator,
    IntelligenceObject,
    IntelligenceRelationship,
)

ADMIN = {"X-CI-User": "investigator", "X-CI-Role": "admin"}


class RecordedProvider(ThreatIntelligenceProvider):
    @property
    def provider_name(self) -> str:
        return "recorded-provider"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type is IndicatorType.URL

    def enrich(self, indicator: NormalizedIndicator) -> IntelligenceFinding | None:
        return IntelligenceFinding(
            provider=self.provider_name,
            indicator=indicator,
            reputation=IndicatorReputation.SUSPICIOUS,
            confidence=0.73,
            observed_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
            reference="https://provider.example.test/finding/1",
            summary="Provider-recorded observation.",
            attack_techniques=("T1071.001",),
            attributes={"classification": "recorded", "api_key": "must-not-persist"},
        )


def _case_with_observed_url(app, client):
    case = client.post(
        "/api/v1/cases",
        headers=ADMIN,
        json={"case_number": "TIP-1", "title": "Intelligence correlation"},
    ).get_json()
    evidence = client.post(
        "/api/v1/evidence",
        headers=ADMIN,
        json={
            "case_id": case["id"],
            "evidence_number": "TIP-E-1",
            "filename": "network.txt",
            "content": "Observed https://example.test/path",
        },
    ).get_json()
    assert client.get(f"/api/v1/evidence/{evidence['id']}/analysis", headers=ADMIN).status_code == 200
    app.extensions["cyberinvestigator_features"].threat_intelligence._engine = ThreatIntelligenceCorrelationEngine(
        (RecordedProvider(),)
    )
    return case, evidence


def test_provider_enrichment_ioc_lifecycle_graph_imports_and_ai_provenance() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    case, evidence = _case_with_observed_url(app, client)
    enriched = client.post("/api/v1/threat-intelligence/enrich", headers=ADMIN, json={"case_id": case["id"]})
    assert enriched.status_code == 200
    assert enriched.get_json()["summary"]["enriched"] == 1

    center = client.get("/api/v1/intelligence-center", headers=ADMIN).get_json()
    indicator = next(
        item for item in center["intelligence_feed"] if item["kind"] == "indicator" and item["indicator_type"] == "url"
    )
    finding = next(item for item in center["intelligence_feed"] if item["kind"] == "object")
    assert finding["source"] == "recorded-provider"
    assert finding["verified"] is False
    assert finding["attributes"]["classification"] == "recorded"
    assert "api_key" not in finding["attributes"]
    assert center["providers"]["available"] is True
    assert center["sharing"]["status"] == "unavailable"
    graph_ids = {node["id"] for node in center["graph"]["nodes"]}
    assert f"evidence:{evidence['id']}" in graph_ids
    assert any(edge["relationship_type"] == "has_provider_finding" for edge in center["graph"]["edges"])
    assert any(edge["relationship_type"] == "preserved_in" for edge in center["graph"]["edges"])

    lifecycle = client.patch(
        f"/api/v1/intelligence-center/iocs/{indicator['id']}",
        headers=ADMIN,
        json={"lifecycle_status": "monitoring"},
    )
    assert lifecycle.status_code == 200
    assert lifecycle.get_json()["lifecycle_status"] == "monitoring"

    actor = client.post(
        "/api/v1/intelligence-center/objects",
        headers=ADMIN,
        json={
            "object_type": "threat_actor",
            "name": "Provider documented actor",
            "external_id": "actor--recorded-1",
            "source": "analyst-reviewed-provider-export",
            "reference": "https://provider.example.test/actor/1",
            "verified": True,
        },
    )
    campaign = client.post(
        "/api/v1/intelligence-center/objects",
        headers=ADMIN,
        json={
            "object_type": "campaign",
            "name": "Provider documented campaign",
            "external_id": "campaign--recorded-1",
            "source": "analyst-reviewed-provider-export",
            "reference": "https://provider.example.test/campaign/1",
            "verified": True,
        },
    )
    assert actor.status_code == campaign.status_code == 201
    relationship = client.post(
        "/api/v1/intelligence-center/relationships",
        headers=ADMIN,
        json={
            "source_kind": "intelligence_object",
            "source_id": actor.get_json()["id"],
            "target_kind": "intelligence_object",
            "target_id": campaign.get_json()["id"],
            "relationship_type": "attributed_by_source",
            "reference": "https://provider.example.test/relationship/1",
            "verified": True,
        },
    )
    assert relationship.status_code == 201
    updated = client.get("/api/v1/intelligence-center", headers=ADMIN).get_json()
    assert updated["threat_actors"][0]["name"] == "Provider documented actor"
    assert updated["campaigns"][0]["name"] == "Provider documented campaign"

    summary = client.post("/api/v1/intelligence-center/ai-summary", headers=ADMIN, json={}).get_json()
    assert summary["provenance"] == "ai_generated_observation"
    assert summary["verified_intelligence"] is False
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        assert database.session.scalar(select(IntelligenceIndicator)) is not None
        assert database.session.scalar(select(IntelligenceRelationship)) is not None
        stored = database.session.scalar(
            select(IntelligenceObject).where(IntelligenceObject.object_type == "provider_finding")
        )
        assert "must-not-persist" not in stored.attributes
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.organization_id == DEFAULT_ORGANIZATION_ID,
                    AuditLog.action.like("intelligence.%"),
                )
            )
        )
        assert {
            "intelligence.object.imported",
            "intelligence.relationship.created",
            "intelligence.ioc.lifecycle_updated",
            "intelligence.ai_summary.requested",
        } <= actions


def test_ioc_search_is_evidence_backed_and_audited_when_providers_unavailable() -> None:
    app = create_app("testing")
    client = app.test_client()
    case = client.post("/api/v1/cases", json={"case_number": "TIP-2", "title": "Search"}).get_json()
    evidence = client.post(
        "/api/v1/evidence",
        json={
            "case_id": case["id"],
            "evidence_number": "TIP-E-2",
            "filename": "ioc.txt",
            "content": "https://example.test/search",
        },
    ).get_json()
    client.get(f"/api/v1/evidence/{evidence['id']}/analysis")
    result = client.post(
        "/api/v1/intelligence-center/iocs/search",
        json={"indicator_type": "url", "indicator_value": "https://example.test/search", "enrich": True},
    )
    assert result.status_code == 200
    assert len(result.get_json()["evidence_matches"]) == 1
    assert result.get_json()["provider_status"] == "unavailable"
    assert result.get_json()["provider_result"]["findings"] == []


def test_intelligence_records_are_isolated_by_organization() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    imported = client.post(
        "/api/v1/intelligence-center/objects",
        headers=ADMIN,
        json={
            "object_type": "campaign",
            "name": "Default tenant campaign",
            "external_id": "campaign--default",
            "source": "reviewed-import",
            "reference": "https://example.test/default",
        },
    )
    assert imported.status_code == 201
    organization = client.post(
        "/api/v1/organizations",
        headers=ADMIN,
        json={"name": "TIP Tenant", "slug": "tip-tenant", "reason": "Isolation test."},
    ).get_json()
    second = {**ADMIN, "X-CI-Organization": organization["id"]}
    center = client.get("/api/v1/intelligence-center", headers=second).get_json()
    assert center["campaigns"] == []
    assert center["intelligence_feed"] == []


def test_intelligence_center_mobile_information_order() -> None:
    html = create_app("testing").test_client().get("/intelligence").get_data(as_text=True)
    labels = ("Intelligence Feed", "IOC Search", "Threat Actors", "Campaigns")
    assert [html.index(label) for label in labels] == sorted(html.index(label) for label in labels)
    assert "intelligence_center.css" in html
    assert 'aria-live="polite"' in html
    assert 'aria-label="Knowledge graph relationships"' in html
