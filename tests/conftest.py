"""Shared pytest fixtures for CyberInvestigator tests.

Note: Integration tests in this repository expect a `db_session` fixture.
Some environments had it missing, causing timeline repository tests to fail
at fixture setup time.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from cyberinvestigator.domain.entities import CaseMetadata, EvidenceItem, InvestigationState


@pytest.fixture
def case_metadata() -> CaseMetadata:
    """Return a minimal, deterministic case metadata record."""
    return CaseMetadata(
        case_id=UUID("11111111-1111-1111-1111-111111111111"),
        case_number="CASE-001",
        title="Test Investigation",
    )


@pytest.fixture
def evidence_item() -> EvidenceItem:
    """Return a representative evidence record without reading a file."""
    return EvidenceItem(
        evidence_id=UUID("22222222-2222-2222-2222-222222222222"),
        evidence_number="E-001",
        filename="evidence.pdf",
        sha256="a" * 64,
        storage_path="/evidence/evidence.pdf",
        media_type="application/pdf",
        size_bytes=1_024,
    )


@pytest.fixture
def investigation_state(case_metadata: CaseMetadata, evidence_item: EvidenceItem) -> InvestigationState:
    """Return an investigation state containing one traceable evidence item."""
    return InvestigationState(case=case_metadata, evidence=[evidence_item])


@pytest.fixture
def unrelated_case_id() -> UUID:
    """Return a case identifier distinct from the shared test case."""
    return uuid4()


@pytest.fixture
def db_session():
    """Provide an isolated SQLAlchemy session for integration tests.

    The timeline repository integration test expects `db_session`.
    We create a transient SQLite database, create all tables, and then yield
    the session.
    """

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from cyberinvestigator.infrastructure.database.base import Base
    from cyberinvestigator.infrastructure.database.models import (  # noqa: F401
        Case,
        Evidence,
        TimelineEvent,
    )

    # Use a single shared in-memory database connection for the whole fixture
    # (SQLite in-memory DBs otherwise get recreated per connection).
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)

    yield session

    # SQLite may normalize tz-aware datetimes; close session to avoid leaks.
    session.close()
