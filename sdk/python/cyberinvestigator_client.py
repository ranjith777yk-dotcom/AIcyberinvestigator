"""Dependency-free preview client for the CyberInvestigator v1 API."""

from __future__ import annotations

import json
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urljoin
from urllib.request import HTTPCookieProcessor, Request, build_opener


class CyberInvestigatorAPIError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class CyberInvestigatorClient:
    """Small preview client; use the OpenAPI contract for complete operations."""

    def __init__(self, base_url: str, *, csrf_token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.csrf_token = csrf_token
        self._opener = build_opener(HTTPCookieProcessor(CookieJar()))

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")
        if method.upper() not in {"GET", "HEAD", "OPTIONS"} and self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        request = Request(
            urljoin(self.base_url, path.lstrip("/")), data=payload, headers=headers, method=method.upper()
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                if response.headers.get("API-Version") != "v1":
                    raise CyberInvestigatorAPIError(response.status, "Unexpected API version.")
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            try:
                document = json.loads(error.read().decode("utf-8"))
                message = str(document.get("error") or "API request failed.")
            except (UnicodeDecodeError, json.JSONDecodeError):
                message = "API request failed."
            raise CyberInvestigatorAPIError(error.code, message) from error

    def readiness(self) -> dict:
        return self.request("GET", "/api/v1/health/ready")

    def openapi(self) -> dict:
        return self.request("GET", "/api/v1/openapi.json")
