from cyberinvestigator.domain.services.timeline_reconstruction import TimelineReconstructionEngine


def test_reconstruction_correlates_only_explicit_shared_sources() -> None:
    events = [
        {
            "id": "event-1",
            "case_id": "case-1",
            "evidence_id": "evidence-1",
            "artifact_id": None,
            "event_type": "evidence.added",
            "summary": "Evidence acquired",
            "occurred_at": "2026-01-01T00:00:00+00:00",
            "created_by": "user-1",
        },
        {
            "id": "event-2",
            "case_id": "case-1",
            "evidence_id": "evidence-1",
            "artifact_id": None,
            "event_type": "evidence.analysis.completed",
            "summary": "Static analysis completed",
            "occurred_at": "2026-01-01T01:00:00+00:00",
            "created_by": "user-1",
        },
        {
            "id": "event-3",
            "case_id": "case-1",
            "evidence_id": None,
            "artifact_id": None,
            "event_type": "observation.manual",
            "summary": "Analyst observation",
            "occurred_at": "2026-01-01T02:00:00+00:00",
            "created_by": "user-1",
        },
    ]
    result = TimelineReconstructionEngine().reconstruct(events)
    assert result["summary"]["confirmed_events"] == 3
    assert result["summary"]["correlated_events"] == 2
    assert result["summary"]["hypotheses"] == 0
    assert result["events"][2]["related_event_ids"] == []


def test_attack_path_requires_recorded_evidence_mapping() -> None:
    event = {
        "id": "event-1",
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "artifact_id": None,
        "event_type": "evidence.analysis.completed",
        "summary": "Analysis complete",
        "occurred_at": "2026-01-01T00:00:00+00:00",
        "created_by": "user-1",
    }
    engine = TimelineReconstructionEngine()
    assert engine.reconstruct([event])["attack_path"] == []
    result = engine.reconstruct(
        [event],
        {
            "evidence-1": {
                "mitre_mapping": [
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "tactic": "Execution",
                        "reason": "PowerShell execution indicator recovered.",
                    }
                ]
            }
        },
    )
    assert result["attack_path"][0]["technique_id"] == "T1059.001"
    assert result["attack_path"][0]["evidence_id"] == "evidence-1"
    assert result["attack_path"][0]["certainty"] == "confirmed"
