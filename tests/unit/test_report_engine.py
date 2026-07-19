"""Unit tests for typed report assembly."""

from cyberinvestigator.domain.entities import CaseMetadata
from cyberinvestigator.domain.services import (
    IndicatorOfCompromise,
    MitreAttackMapping,
    ReportEngine,
    ReportRequest,
)


def test_report_engine_preserves_all_supplied_report_sections(case_metadata: CaseMetadata) -> None:
    """Report assembly retains supplied summaries, mappings, and IOCs unchanged."""
    mapping = MitreAttackMapping(technique_id="T0000", technique_name="Example", tactic="Example tactic")
    indicator = IndicatorOfCompromise(indicator_type="domain", value="example.invalid", confidence=0.9)
    request = ReportRequest(
        case=case_metadata,
        executive_summary="Executive summary",
        technical_summary="Technical summary",
        mitre_attack_mappings=(mapping,),
        indicators_of_compromise=(indicator,),
    )

    report = ReportEngine().build_report(request)

    assert report.case is case_metadata
    assert report.mitre_attack_mappings == (mapping,)
    assert report.indicators_of_compromise == (indicator,)
