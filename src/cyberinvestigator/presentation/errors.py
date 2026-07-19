"""Central HTTP error handling for the Flask presentation boundary."""

from __future__ import annotations

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException


def register_error_handlers(app: Flask) -> None:
    """Register consistent client-safe HTTP error responses.

    Returned responses never expose:
    - request path
    - stack traces
    - filesystem paths

    Full error details are logged server-side.
    """

    def _error_response(*, error_id: str, status: int) -> dict[str, object]:
        # RFC3339-ish timestamp without introducing external dependencies.
        # (Client does not need exact timezone parsing.)
        from datetime import datetime, timezone

        return {
            "error_id": error_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "An error occurred while processing the request.",
            "status": status,
        }

    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException) -> ResponseReturnValue:
        """Return a safe JSON response for expected HTTP failures."""
        from uuid import uuid4

        error_id = str(uuid4())
        # Log internal details, including the request context, but avoid returning
        # sensitive fields to the client.
        app.logger.warning(
            "HTTP request failed: %s (status=%s) error_id=%s path=%s",
            error.name,
            error.code,
            error_id,
            request.path,
        )

        return jsonify(_error_response(error_id=error_id, status=error.code)), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error: Exception) -> ResponseReturnValue:
        """Log unexpected errors without exposing internal details."""
        from uuid import uuid4

        error_id = str(uuid4())
        app.logger.exception(
            "Unhandled application error error_id=%s path=%s",
            error_id,
            request.path,
            exc_info=error,
        )
        return jsonify(_error_response(error_id=error_id, status=500)), 500

    @app.after_request
    def apply_security_headers(response):  # type: ignore[no-untyped-def]
        """Apply conservative browser security headers to every HTTP response."""
        if not bool(app.config.get("SECURITY_HEADERS_ENABLED", True)):
            return response

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response
