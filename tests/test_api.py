from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from ragsentry.api.app import create_app
from ragsentry.api.jobs import JobManager, JobStatus
from ragsentry.auditor.models import AuditReport, Finding, Severity
from ragsentry.auditor.probes import Probe
from ragsentry.auditor.scoring import build_report
from ragsentry.config import Settings
from ragsentry.target.pipeline import TargetResponse, TargetUnavailableError, VulnerableRAG


class StubRAG(VulnerableRAG):
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def query(self, question: str) -> TargetResponse:
        if self.fail:
            raise TargetUnavailableError("upstream down")
        return TargetResponse(answer=f"echo: {question}", sources=["a.txt"])


def instant_audit(
    probes: Sequence[Probe], on_progress: Callable[[str, Finding], None]
) -> AuditReport:
    findings = []
    for probe in probes:
        finding = Finding(
            probe_id=probe.id,
            vulnerability_type=probe.vulnerability_type,
            score=5,
            severity=Severity.MEDIUM,
            reasoning="r",
        )
        on_progress(probe.id, finding)
        findings.append(finding)
    now = datetime.now(timezone.utc)
    return build_report(findings, now, now)


def wait_for(client: TestClient, job_id: str, timeout: float = 5.0) -> dict:  # type: ignore[type-arg]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/audits/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            return job  # type: ignore[no-any-return]
        time.sleep(0.02)
    raise AssertionError("audit did not finish")


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings, target=StubRAG(), audit_fn=instant_audit))


def test_health(client: TestClient) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["groq_configured"] is True
    assert body["index_ready"] is False


def test_query_target(client: TestClient) -> None:
    resp = client.post("/api/target/query", json={"prompt": "hello"})
    assert resp.status_code == 200
    assert resp.json() == {"response": "echo: hello", "sources": ["a.txt"]}


@pytest.mark.parametrize("payload", [{}, {"prompt": ""}, {"prompt": "   "}])
def test_query_validation(client: TestClient, payload: dict) -> None:  # type: ignore[type-arg]
    assert client.post("/api/target/query", json=payload).status_code == 422


def test_query_too_long(settings: Settings) -> None:
    small = settings.model_copy(update={"max_prompt_chars": 5})
    client = TestClient(create_app(small, target=StubRAG(), audit_fn=instant_audit))
    assert client.post("/api/target/query", json={"prompt": "too long"}).status_code == 422


def test_query_upstream_failure_is_502(settings: Settings) -> None:
    client = TestClient(create_app(settings, target=StubRAG(fail=True), audit_fn=instant_audit))
    resp = client.post("/api/target/query", json={"prompt": "hi"})
    assert resp.status_code == 502
    assert "upstream down" in resp.json()["detail"]


def test_endpoints_require_key(settings: Settings) -> None:
    no_key = settings.model_copy(update={"groq_api_key": None})
    client = TestClient(create_app(no_key, target=StubRAG(), audit_fn=instant_audit))
    assert client.post("/api/target/query", json={"prompt": "hi"}).status_code == 503
    assert client.post("/api/audits").status_code == 503
    assert client.get("/api/health").json()["groq_configured"] is False


def test_audit_lifecycle(client: TestClient) -> None:
    resp = client.post("/api/audits")
    assert resp.status_code == 202
    job = wait_for(client, resp.json()["id"])
    assert job["status"] == "completed"
    assert all(p["done"] for p in job["probes"])
    assert job["report"]["overall_severity"] == "Medium"
    assert job["finished_at"] is not None


def test_unknown_audit_is_404(client: TestClient) -> None:
    assert client.get("/api/audits/nope").status_code == 404


def test_concurrent_audit_is_rejected(settings: Settings) -> None:
    release = threading.Event()

    def slow_audit(
        probes: Sequence[Probe], on_progress: Callable[[str, Finding], None]
    ) -> AuditReport:
        release.wait(5)
        return instant_audit(probes, on_progress)

    client = TestClient(create_app(settings, target=StubRAG(), audit_fn=slow_audit))
    first = client.post("/api/audits").json()
    second = client.post("/api/audits")
    assert second.status_code == 409
    assert second.json()["detail"]["job_id"] == first["id"]
    release.set()
    assert wait_for(client, first["id"])["status"] == "completed"


def test_failed_audit_reports_error() -> None:
    def broken(probes: Sequence[Probe], on_progress: Callable[[str, Finding], None]) -> AuditReport:
        raise RuntimeError("kaboom")

    manager = JobManager(broken)
    job = manager.submit()
    deadline = time.monotonic() + 5
    while (current := manager.get(job.id)) and not current.finished:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert current is not None
    assert current.status is JobStatus.FAILED
    assert current.error == "RuntimeError: kaboom"
    manager.shutdown()


def test_job_history_is_bounded() -> None:
    manager = JobManager(instant_audit, max_history=2)
    ids = []
    for _ in range(4):
        job = manager.submit()
        ids.append(job.id)
        while not (manager.get(job.id) or job).finished:
            time.sleep(0.01)
    assert manager.get(ids[0]) is None
    assert manager.get(ids[-1]) is not None
    manager.shutdown()
