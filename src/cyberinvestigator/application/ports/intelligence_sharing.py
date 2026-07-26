"""Standards-sharing adapter boundary for future STIX/TAXII integrations."""

from __future__ import annotations

from typing import Mapping, Protocol


class IntelligenceSharingAdapter(Protocol):
    identifier: str

    def availability(self) -> Mapping[str, object]: ...

    def import_bundle(self, bundle: Mapping[str, object]) -> Mapping[str, object]: ...

    def export_bundle(self, object_ids: tuple[str, ...]) -> Mapping[str, object]: ...


class UnavailableIntelligenceSharingAdapter:
    identifier = "stix-taxii-unconfigured"

    def availability(self) -> Mapping[str, object]:
        return {
            "adapter": self.identifier,
            "configured": False,
            "status": "unavailable",
            "import_enabled": False,
            "export_enabled": False,
            "reason": "No authenticated STIX/TAXII sharing adapter is configured.",
        }

    def import_bundle(self, bundle: Mapping[str, object]) -> Mapping[str, object]:
        del bundle
        return {"status": "unavailable", "adapter": self.identifier}

    def export_bundle(self, object_ids: tuple[str, ...]) -> Mapping[str, object]:
        del object_ids
        return {"status": "unavailable", "adapter": self.identifier}
