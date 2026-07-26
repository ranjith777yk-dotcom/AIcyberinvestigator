"""Truthful process, database, storage, cache, and queue capacity inspection."""

from __future__ import annotations

import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path


class PerformanceInspector:
    def __init__(self, instance_path: Path) -> None:
        self.instance_path = instance_path.resolve()
        self.started_at = time.time()

    def snapshot(self, *, database, telemetry, cache, dispatcher) -> dict[str, object]:
        return {
            "collected_at": datetime.now(UTC).isoformat(),
            "platform_health": {
                "process_uptime_seconds": round(time.time() - self.started_at, 3),
                "request_telemetry": telemetry.snapshot(),
                "process_id": os.getpid(),
            },
            "capacity": {
                "logical_cpu_count": os.cpu_count(),
                "process_memory": self._process_memory(),
                "storage": self._storage(),
                "database_pool": self._database_pool(database),
                "replica_count": None,
                "replica_detail": "Replica discovery requires an orchestrator or infrastructure metrics connector.",
            },
            "queue_status": dispatcher.snapshot(),
            "cache": cache.snapshot(),
            "bottlenecks": self._bottlenecks(dispatcher.snapshot(), cache.snapshot()),
            "high_availability": {
                "web_process_scaling": "configured_by_runtime",
                "durable_job_queue": False,
                "shared_cache": False,
                "database_failover": "external",
                "shared_evidence_storage": "external",
                "load_balancer": "unavailable",
                "detail": "HA components are reported only when connected; this process cannot discover external topology.",
            },
        }

    def _storage(self) -> dict[str, object]:
        try:
            usage = shutil.disk_usage(self.instance_path)
        except OSError as error:
            return {"status": "unavailable", "detail": str(error)}
        return {
            "status": "available",
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": round(usage.used / usage.total * 100, 3) if usage.total else None,
            "scope": "instance_volume_filesystem",
        }

    @staticmethod
    def _process_memory() -> dict[str, object]:
        try:
            import resource

            value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            multiplier = 1 if os.name == "nt" else 1024
            return {"status": "available", "peak_resident_bytes": int(value * multiplier), "source": "getrusage"}
        except (ImportError, OSError, ValueError):
            return {"status": "unavailable", "detail": "A supported process memory collector is not available."}

    @staticmethod
    def _database_pool(database) -> dict[str, object]:
        pool = database.engine.pool
        result: dict[str, object] = {"provider": pool.__class__.__name__}
        for name in ("size", "checkedin", "checkedout", "overflow"):
            operation = getattr(pool, name, None)
            try:
                result[name] = operation() if callable(operation) else None
            except (AttributeError, NotImplementedError):
                result[name] = None
        result["scope"] = "current_process"
        return result

    @staticmethod
    def _bottlenecks(queue: dict[str, object], cache: dict[str, object]) -> list[dict[str, object]]:
        findings = []
        if int(queue["queued"]) > 0 and int(queue["available_workers"]) == 0:
            findings.append({"component": "background_jobs", "status": "saturated", "evidence": queue})
        if int(cache["evictions"]) > 0:
            findings.append(
                {"component": "process_cache", "status": "capacity_pressure", "evictions": cache["evictions"]}
            )
        return findings
