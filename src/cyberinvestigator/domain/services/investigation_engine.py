"""Interfaces for the platform-wide investigation engine.

This module defines orchestration boundaries only.  It does not execute tools,
invoke AI providers, mutate workflows, or implement persistence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from cyberinvestigator.domain.entities.investigation_state import CaseMetadata, InvestigationState


@dataclass(frozen=True, slots=True, kw_only=True)
class EngineDescriptor:
    """Immutable identity and capability declaration for a coordinated engine."""

    identifier: str
    name: str
    version: str
    capabilities: tuple[str, ...] = ()


class CoordinatedEngine(Protocol):
    """Minimal contract for an engine that can be registered for coordination."""

    @property
    def descriptor(self) -> EngineDescriptor:
        """Return the engine's immutable identity and capability declaration."""
        ...


class InvestigationStateStore(Protocol):
    """Persistence boundary for reusable investigation state snapshots."""

    def create(self, state: InvestigationState) -> None:
        """Persist a newly created investigation state snapshot."""
        ...

    def load(self, case_id: UUID) -> InvestigationState:
        """Load the current investigation state for one case."""
        ...

    def save(self, state: InvestigationState) -> None:
        """Persist the current version of an investigation state snapshot."""
        ...


class EngineRegistry(Protocol):
    """Registry boundary for engines coordinated by an investigation engine."""

    def register(self, engine: CoordinatedEngine) -> None:
        """Register one engine for participation in investigation coordination."""
        ...

    def unregister(self, engine_identifier: str) -> None:
        """Remove a registered engine by its stable identifier."""
        ...

    def list_registered(self) -> tuple[EngineDescriptor, ...]:
        """Return metadata for all engines available to the coordinator."""
        ...


class InvestigationEngine(ABC):
    """Abstract coordinator for the lifecycle and shared state of a case.

    Implementations own the lifecycle boundary and state maintenance. They must
    delegate concrete tool execution and AI interaction to separately defined,
    explicitly authorised components.
    """

    @property
    @abstractmethod
    def state_store(self) -> InvestigationStateStore:
        """Return the persistence boundary used to maintain investigation state."""
        ...

    @property
    @abstractmethod
    def engine_registry(self) -> EngineRegistry:
        """Return the registry of engines available for coordination."""
        ...

    @abstractmethod
    def start_investigation(self, case: CaseMetadata) -> InvestigationState:
        """Start a case and return its initial reusable investigation state."""
        ...

    @abstractmethod
    def resume_investigation(self, case_id: UUID) -> InvestigationState:
        """Resume a case by loading and returning its current investigation state."""
        ...

    @abstractmethod
    def stop_investigation(self, case_id: UUID) -> InvestigationState:
        """Stop a case and return its final persisted investigation state."""
        ...

    @abstractmethod
    def get_investigation_state(self, case_id: UUID) -> InvestigationState:
        """Return the current state without changing the investigation lifecycle."""
        ...

    @abstractmethod
    def save_investigation_state(self, state: InvestigationState) -> None:
        """Persist a state supplied by a coordinating component."""
        ...

    @abstractmethod
    def coordinate_engines(self, case_id: UUID) -> None:
        """Coordinate registered engines for a case without defining their execution."""
        ...
