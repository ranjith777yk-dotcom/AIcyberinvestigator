"""Evidence-backed timeline reconstruction without speculative attack stages."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable


class TimelineReconstructionEngine:
    """Correlate persisted events using explicit case, evidence, and artifact links."""

    def reconstruct(
        self,
        events: Iterable[dict[str, object]],
        evidence_reports: dict[str, dict[str, object]] | None = None,
    ) -> dict[str, object]:
        records = list(events)
        reports = evidence_reports or {}
        related: dict[str, set[str]] = defaultdict(set)
        for index, event in enumerate(records):
            for other in records[index + 1 :]:
                shared = self._shared_source(event, other)
                if shared:
                    related[str(event["id"])].add(str(other["id"]))
                    related[str(other["id"])].add(str(event["id"]))

        normalized = []
        attack_path = []
        for event in sorted(records, key=lambda item: str(item.get("occurred_at") or "")):
            source_type = (
                "evidence"
                if event.get("evidence_id")
                else "artifact"
                if event.get("artifact_id")
                else "manual"
                if event.get("event_type") == "observation.manual"
                else "system"
            )
            normalized.append(
                {
                    **event,
                    "certainty": "confirmed",
                    "source_type": source_type,
                    "related_event_ids": sorted(related[str(event["id"])]),
                    "provenance": {
                        "case_id": event.get("case_id"),
                        "evidence_id": event.get("evidence_id"),
                        "artifact_id": event.get("artifact_id"),
                        "created_by": event.get("created_by"),
                    },
                }
            )
            evidence_id = str(event.get("evidence_id") or "")
            report = reports.get(evidence_id, {})
            mappings = report.get("mitre_mapping", []) if isinstance(report, dict) else []
            for mapping in mappings if isinstance(mappings, list) else []:
                if not isinstance(mapping, dict) or not mapping.get("technique_id"):
                    continue
                attack_path.append(
                    {
                        "event_id": event["id"],
                        "occurred_at": event.get("occurred_at"),
                        "technique_id": mapping["technique_id"],
                        "technique_name": mapping.get("technique_name") or mapping.get("name"),
                        "tactic": mapping.get("tactic"),
                        "reason": mapping.get("reason"),
                        "evidence_id": evidence_id,
                        "certainty": "confirmed",
                    }
                )

        edges = [
            {"source": event_id, "target": related_id, "type": "shared_source"}
            for event_id, related_ids in related.items()
            for related_id in sorted(related_ids)
            if event_id < related_id
        ]
        return {
            "events": normalized,
            "summary": {
                "confirmed_events": len(normalized),
                "hypotheses": 0,
                "correlated_events": sum(1 for item in normalized if item["related_event_ids"]),
                "evidence_links": len({str(item["evidence_id"]) for item in normalized if item.get("evidence_id")}),
                "artifact_links": len({str(item["artifact_id"]) for item in normalized if item.get("artifact_id")}),
            },
            "attack_path": attack_path,
            "hypotheses": [],
            "explainability": (
                "Attack progression includes only ATT&CK mappings recorded by evidence analysis. "
                "Persisted events are confirmed records; no attack stages were inferred."
            ),
            "graph": {
                "nodes": [
                    {"id": item["id"], "type": "timeline_event", "label": item["summary"]} for item in normalized
                ],
                "edges": edges,
            },
        }

    @staticmethod
    def _shared_source(left: dict[str, object], right: dict[str, object]) -> bool:
        return any(
            left.get(field) is not None and left.get(field) == right.get(field)
            for field in ("evidence_id", "artifact_id")
        )
