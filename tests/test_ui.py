from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from ragsentry.ui.client import ApiError, RagSentryClient

APP = str(Path(__file__).parents[1] / "src" / "ragsentry" / "ui" / "app.py")


def test_client_maps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/audits":
            return httpx.Response(409, json={"detail": {"message": "busy", "job_id": "j1"}})
        return httpx.Response(422, json={"detail": [{"msg": "bad prompt"}]})

    transport = httpx.MockTransport(handler)
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda *a, **kw: original(*a, transport=transport, **kw))
    client = RagSentryClient("http://api.test")

    with pytest.raises(ApiError) as busy:
        client.start_audit()
    assert busy.value.status_code == 409
    assert busy.value.message == "busy"
    assert busy.value.detail["job_id"] == "j1"

    with pytest.raises(ApiError, match="bad prompt"):
        client.query_target("x")


def test_client_reports_offline_api() -> None:
    client = RagSentryClient("http://127.0.0.1:9")
    with pytest.raises(ApiError, match="Cannot reach"):
        client.health()


def test_dashboard_renders_when_api_is_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAGSENTRY_API_URL", "http://127.0.0.1:9")
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert any("API offline" in e.value for e in at.sidebar.error)
    start = next(b for b in at.button if b.label == "Start audit")
    assert start.disabled
