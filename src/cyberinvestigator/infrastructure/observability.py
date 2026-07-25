"""Bounded request telemetry, W3C trace correlation, and secret redaction."""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from flask import Flask, Response, g, has_request_context, request

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(https?://[^/\s:@]+:)[^@\s/]+@"),
)


def redact_text(value: object, *, known_secrets: tuple[str, ...] = ()) -> str:
    """Remove common credential forms from operational text."""
    text = str(value)
    for secret in known_secrets:
        if len(secret) >= 4:
            text = text.replace(secret, "[REDACTED]")
    for pattern in _SENSITIVE_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


class SecretRedactionFilter(logging.Filter):
    """Redact message text before any configured handler persists it."""

    def __init__(self, known_secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.known_secrets = known_secrets

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage(), known_secrets=self.known_secrets)
        record.args = ()
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Emit one normalized JSON event per log line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
            "process": record.process,
            "request_id": getattr(g, "request_id", None) if has_request_context() else None,
            "trace_id": getattr(g, "trace_id", None) if has_request_context() else None,
            "span_id": getattr(g, "span_id", None) if has_request_context() else None,
        }
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class RequestTrace:
    timestamp: float
    request_id: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    method: str
    path: str
    endpoint: str | None
    status: int
    duration_ms: float


class TelemetryRegistry:
    """Thread-safe bounded request history for one application process."""

    def __init__(self, *, max_traces: int = 5000) -> None:
        self.started_at = time.time()
        self._traces: deque[RequestTrace] = deque(maxlen=max_traces)
        self._status = Counter()
        self._routes = Counter()
        self._lock = threading.RLock()
        self.max_traces = max_traces

    def record(self, trace: RequestTrace) -> None:
        with self._lock:
            self._traces.append(trace)
            self._status[str(trace.status)] += 1
            self._routes[f"{trace.method} {trace.endpoint or '<unmatched>'}"] += 1

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            traces = list(self._traces)
            statuses = dict(self._status)
            routes = dict(self._routes.most_common(20))
        durations = sorted(item.duration_ms for item in traces)
        observed_seconds = max(0.0, time.time() - self.started_at)
        request_total = sum(statuses.values())
        server_errors = sum(count for status, count in statuses.items() if int(status) >= 500)
        return {
            "requests_total": request_total,
            "server_errors_total": server_errors,
            "server_error_rate": round(server_errors / request_total, 6) if request_total else None,
            "status_counts": statuses,
            "top_routes": routes,
            "latency_ms": {
                "sample_count": len(durations),
                "minimum": durations[0] if durations else None,
                "median": _percentile(durations, 0.5),
                "p95": _percentile(durations, 0.95),
                "maximum": durations[-1] if durations else None,
            },
            "throughput": {
                "requests_per_second": round(request_total / observed_seconds, 4) if observed_seconds > 0 else None,
                "observed_seconds": round(observed_seconds, 3),
            },
            "history": _minute_history(traces),
            "retention": {
                "scope": "current_process",
                "max_traces": self.max_traces,
                "retained_traces": len(traces),
                "started_at": datetime.fromtimestamp(self.started_at, UTC).isoformat(),
            },
        }

    def recent_traces(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            records = list(self._traces)[-max(1, min(limit, 500)) :]
        return [asdict(item) for item in reversed(records)]


def register_observability(app: Flask) -> None:
    """Register request instrumentation without changing application routes."""
    registry = TelemetryRegistry(max_traces=int(app.config.get("OBSERVABILITY_MAX_TRACES", 5000)))
    app.extensions["cyberinvestigator_telemetry"] = registry

    @app.before_request
    def begin_observed_request() -> None:
        supplied = str(request.headers.get("traceparent") or "").lower()
        match = _TRACEPARENT.fullmatch(supplied)
        valid_parent = bool(match and match.group(1) != "0" * 32 and match.group(2) != "0" * 16)
        supplied_request_id = str(request.headers.get("X-Request-ID") or "")
        g.request_id = supplied_request_id if _REQUEST_ID.fullmatch(supplied_request_id) else secrets.token_hex(16)
        g.trace_id = match.group(1) if valid_parent and match else secrets.token_hex(16)
        g.parent_span_id = match.group(2) if valid_parent and match else None
        g.trace_flags = match.group(3) if match else "01"
        g.span_id = secrets.token_hex(8)
        g.observability_started_at = time.perf_counter()

    @app.after_request
    def finish_observed_request(response: Response) -> Response:
        duration_ms = round((time.perf_counter() - g.observability_started_at) * 1000, 3)
        trace = RequestTrace(
            timestamp=time.time(),
            request_id=str(g.request_id),
            trace_id=str(g.trace_id),
            span_id=str(g.span_id),
            parent_span_id=g.parent_span_id,
            method=request.method,
            path=request.url_rule.rule if request.url_rule is not None else "<unmatched>",
            endpoint=request.endpoint,
            status=response.status_code,
            duration_ms=duration_ms,
        )
        registry.record(trace)
        response.headers.setdefault("traceparent", f"00-{g.trace_id}-{g.span_id}-{g.trace_flags}")
        response.headers.setdefault("Server-Timing", f"app;dur={duration_ms}")
        return response


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    index = min(len(values) - 1, max(0, round((len(values) - 1) * fraction)))
    return values[index]


def _minute_history(traces: list[RequestTrace]) -> list[dict[str, object]]:
    buckets: dict[str, dict[str, object]] = {}
    for trace in traces:
        minute = datetime.fromtimestamp(trace.timestamp, UTC).replace(second=0, microsecond=0).isoformat()
        bucket = buckets.setdefault(minute, {"minute": minute, "requests": 0, "errors": 0, "duration_total_ms": 0.0})
        bucket["requests"] = int(bucket["requests"]) + 1
        bucket["errors"] = int(bucket["errors"]) + int(trace.status >= 500)
        bucket["duration_total_ms"] = float(bucket["duration_total_ms"]) + trace.duration_ms
    history = []
    for bucket in buckets.values():
        requests = int(bucket["requests"])
        history.append(
            {
                "minute": bucket["minute"],
                "requests": requests,
                "errors": bucket["errors"],
                "average_latency_ms": round(float(bucket["duration_total_ms"]) / requests, 3),
            }
        )
    return history[-120:]
