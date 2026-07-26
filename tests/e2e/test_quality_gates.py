from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from cyberinvestigator import create_app

playwright = pytest.importorskip("playwright.sync_api")


@contextmanager
def live_application():
    app = create_app("testing")
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", app
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_admin_quality_workspace_across_required_viewports() -> None:
    with live_application() as (base_url, _app), playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            for width, height in ((1440, 900), (1024, 768), (768, 1024), (390, 844)):
                page = browser.new_page(viewport={"width": width, "height": height})
                page.goto(f"{base_url}/admin/quality", wait_until="networkidle")
                assert page.get_by_role("heading", name="Testing, Quality Assurance & Security Validation").is_visible()
                assert page.locator("#test-status").is_visible()
                assert page.locator("#failed-runs").is_visible()
                assert page.locator("#security-findings").is_visible()
                assert page.locator("#coverage-summary").is_visible()
                assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
                page.close()
        finally:
            browser.close()


@pytest.mark.e2e
def test_quality_workspace_has_keyboard_and_landmark_basics() -> None:
    with live_application() as (base_url, app), playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            page = browser.new_page()
            page.goto(f"{base_url}/admin/quality", wait_until="networkidle")
            assert page.locator("main").count() == 1
            assert page.locator("h1, h2").count() >= 1
            assert page.locator("[role=status][aria-live=polite]").count() >= 1
            page.keyboard.press("Tab")
            assert page.evaluate("document.activeElement !== document.body")
            report_dir = Path(app.config["INSTANCE_PATH"]) / "quality"
            report_dir.mkdir(parents=True, exist_ok=True)
            report = {
                "page": "/admin/quality",
                "checks": 4,
                "violations": 0,
                "scope": "automated keyboard and semantic landmark checks",
            }
            (report_dir / "accessibility-summary.json").write_text(json.dumps(report), encoding="utf-8")
        finally:
            browser.close()


@pytest.mark.performance
def test_health_endpoint_latency_budget_records_real_measurements(tmp_path: Path) -> None:
    samples: list[float] = []
    with live_application() as (base_url, app), playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            page = browser.new_page()
            for _ in range(10):
                started = time.perf_counter()
                response = page.request.get(f"{base_url}/api/v1/health/ready")
                samples.append((time.perf_counter() - started) * 1000)
                assert response.ok
        finally:
            browser.close()
        report_dir = Path(app.config["INSTANCE_PATH"]) / "quality"
        report_dir.mkdir(parents=True, exist_ok=True)
        ordered = sorted(samples)
        report = {
            "endpoint": "/api/v1/health/ready",
            "sample_count": len(samples),
            "p95_milliseconds": round(ordered[max(0, int(len(ordered) * 0.95) - 1)], 3),
            "maximum_milliseconds": round(max(samples), 3),
            "budget_milliseconds": 1000,
        }
        (report_dir / "performance-summary.json").write_text(json.dumps(report), encoding="utf-8")
        assert report["p95_milliseconds"] < report["budget_milliseconds"]
