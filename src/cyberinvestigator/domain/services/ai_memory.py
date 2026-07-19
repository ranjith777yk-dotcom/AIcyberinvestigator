"""LLM-independent architecture for structured AI investigation memory.

The module defines typed memory records and persistence boundaries only.  It
does not connect to an LLM, embedding service, vector store, database, or tool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol
from uuid import UUID, uuid4


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for memory record metadata."""
    return datetime.now(timezone.utc)


class MemoryKind(str, Enum):
    """Supported categories of structured investigation memory."""

    INVESTIGATION = "investigation"
    EVIDENCE = "evidence"
    TOOL = "tool"
    REASONING = "reasoning"
    TIMELINE = "timeline"
    CONVERSATION = "conversation"


@dataclass(frozen=True, slots=True, kw_only=True)
class MemoryEntry(ABC):
    """Common immutable metadata shared by every memory record."""

    case_id: UUID
    content: str
    memory_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=utc_now)
    source_reference: str | None = None

    @property
    @abstractmethod
    def kind(self) -> MemoryKind:
        """Return the category represented by this memory entry."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationMemory(MemoryEntry):
    """Case-level memory such as scope, objectives, and recorded context."""

    @property
    def kind(self) -> MemoryKind:
        """Return the investigation memory category."""
        return MemoryKind.INVESTIGATION


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceMemory(MemoryEntry):
    """Memory associated with a specific evidence record."""

    evidence_id: UUID

    @property
    def kind(self) -> MemoryKind:
        """Return the evidence memory category."""
        return MemoryKind.EVIDENCE


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolMemory(MemoryEntry):
    """Memory associated with a recorded tool execution reference."""

    tool_execution_id: UUID

    @property
    def kind(self) -> MemoryKind:
        """Return the tool memory category."""
        return MemoryKind.TOOL


@dataclass(frozen=True, slots=True, kw_only=True)
class ReasoningMemory(MemoryEntry):
    """Memory associated with an auditable reasoning record."""

    reasoning_id: UUID

    @property
    def kind(self) -> MemoryKind:
        """Return the reasoning memory category."""
        return MemoryKind.REASONING


@dataclass(frozen=True, slots=True, kw_only=True)
class TimelineMemory(MemoryEntry):
    """Memory associated with a timeline observation reference."""

    timeline_event_id: UUID

    @property
    def kind(self) -> MemoryKind:
        """Return the timeline memory category."""
        return MemoryKind.TIMELINE


@dataclass(frozen=True, slots=True, kw_only=True)
class ConversationMemory(MemoryEntry):
    """Memory associated with one recorded investigation conversation message."""

    conversation_id: UUID
    message_role: str

    @property
    def kind(self) -> MemoryKind:
        """Return the conversation memory category."""
        return MemoryKind.CONVERSATION


MemoryRecord = InvestigationMemory | EvidenceMemory | ToolMemory | ReasoningMemory | TimelineMemory | ConversationMemory
"""Union of all supported typed AI memory records."""


class AIMemoryStore(Protocol):
    """Persistence boundary for structured AI memory records."""

    def save(self, memory: MemoryRecord) -> None:
        """Persist one immutable memory record."""
        ...

    def get(self, memory_id: UUID) -> MemoryRecord:
        """Retrieve one memory record by its stable identifier."""
        ...

    def list_for_case(self, case_id: UUID, kind: MemoryKind | None = None) -> tuple[MemoryRecord, ...]:
        """Retrieve records for a case, optionally limited to one memory category."""
        ...


class AIMemorySystem(ABC):
    """Abstract façade for recording and retrieving investigation memory.

    Concrete systems can compose persistence, access control, retention, and
    retrieval policies without coupling this domain architecture to an LLM.
    """

    @property
    @abstractmethod
    def store(self) -> AIMemoryStore:
        """Return the configured memory persistence boundary."""
        ...

    @abstractmethod
    def record(self, memory: MemoryRecord) -> None:
        """Record one typed memory entry."""
        ...

    @abstractmethod
    def retrieve(self, case_id: UUID, kind: MemoryKind | None = None) -> tuple[MemoryRecord, ...]:
        """Retrieve typed memory records for a case."""
        ...
