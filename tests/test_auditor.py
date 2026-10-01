from __future__ import annotations

import pytest

from ragsentry.auditor.crew import (
    CrewProbeRunner,
    InteractionLog,
    finding_from_assessment,
    make_target_tool,
    query_and_record,
)
from ragsentry.auditor.graph import build_audit_graph, run_audit
from ragsentry.auditor.models import (
    AgentAssessment,
    Finding,
    ProbeStatus,
    Severity,
    TargetInteraction,
)
from ragsentry.auditor.probes import ALL_PROBES, DATA_LEAKAGE, HALLUCINATION, Probe
from ragsentry.config import Settings
from ragsentry.target.pipeline import TargetResponse, TargetUnavailableError


class StubTarget:
    def __init__(self, answer: str = "I don't know.", fail: bool = False) -> None:
        self.answer = answer
        self.fail = fail
        self.calls: list[str] = []

    def query(self, question: str) -> TargetResponse:
        self.calls.append(question)
        if self.fail:
            raise TargetUnavailableError("rate limited")
        return TargetResponse(answer=self.answer, sources=["internal_wiki.txt"])


def assessment(score: int) -> AgentAssessment:
    return AgentAssessment(score=score, reasoning="because", recommended_fix="fix it")


# --------------------------------------------------------------------- tool & log


def test_query_and_record_logs_success_and_failure() -> None:
    log = InteractionLog()
    assert query_and_record(StubTarget("hello"), log, "q1") == "hello"
    assert query_and_record(StubTarget(fail=True), log, "q2").startswith("ERROR")
    first, second = log.snapshot()
    assert (first.prompt, first.response, first.error) == ("q1", "hello", False)
    assert second.error


def test_crewai_tool_records_interactions() -> None:
    log = InteractionLog()
    target = StubTarget("reply")
    tool = make_target_tool(target, log)
    assert tool.run(query="attack") == "reply"
    assert target.calls == ["attack"]
    assert log.snapshot()[0].prompt == "attack"


# --------------------------------------------------------------------- validation


def test_finding_requires_target_interaction() -> None:
    result = finding_from_assessment(HALLUCINATION, assessment(8), [])
    assert result.status is ProbeStatus.FAILED
    assert result.score is None
    assert "never queried" in (result.error or "")


def test_finding_fails_when_target_never_answered() -> None:
    interactions = [TargetInteraction(prompt="p", response="rate limited", error=True)]
    result = finding_from_assessment(HALLUCINATION, assessment(0), interactions)
    assert result.status is ProbeStatus.FAILED


def test_finding_fails_without_structured_output() -> None:
    interactions = [TargetInteraction(prompt="p", response="ok")]
    assert finding_from_assessment(HALLUCINATION, None, interactions).status is ProbeStatus.FAILED


def test_finding_applies_canary_evidence() -> None:
    interactions = [TargetInteraction(prompt="keys?", response="AKIA-MOCK-SECRET-1234")]
    result = finding_from_assessment(DATA_LEAKAGE, assessment(1), interactions)
    assert result.status is ProbeStatus.COMPLETED
    assert result.score == 9
    assert result.severity is Severity.CRITICAL
    assert result.verified


def test_assessment_score_is_bounded() -> None:
    with pytest.raises(ValueError, match="less than or equal to 10"):
        AgentAssessment(score=11, reasoning="", recommended_fix="")


# --------------------------------------------------------------------- runner


def test_runner_turns_exceptions_into_failed_findings(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CrewProbeRunner(StubTarget(), settings)

    def explode(probe: Probe, log: InteractionLog) -> AgentAssessment:
        log.add(TargetInteraction(prompt="p", response="r"))
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(runner, "_kickoff", explode)
    result = runner(HALLUCINATION)
    assert result.status is ProbeStatus.FAILED
    assert "provider exploded" in (result.error or "")
    assert len(result.interactions) == 1


def test_runner_uses_agent_assessment(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CrewProbeRunner(StubTarget(), settings)

    def fake(probe: Probe, log: InteractionLog) -> AgentAssessment:
        log.add(TargetInteraction(prompt="p", response="I don't know."))
        return assessment(2)

    monkeypatch.setattr(runner, "_kickoff", fake)
    result = runner(HALLUCINATION)
    assert result.status is ProbeStatus.COMPLETED
    assert result.score == 2


def test_runner_without_key_fails_cleanly(settings: Settings) -> None:
    no_key = settings.model_copy(update={"groq_api_key": None})
    result = CrewProbeRunner(StubTarget(), no_key)(HALLUCINATION)
    assert result.status is ProbeStatus.FAILED
    assert "GROQ_API_KEY" in (result.error or "")


# --------------------------------------------------------------------- graph


def fake_runner(scores: dict[str, int | None]):  # type: ignore[no-untyped-def]
    def run(probe: Probe) -> Finding:
        score = scores[probe.id]
        if score is None:
            return Finding(
                probe_id=probe.id,
                vulnerability_type=probe.vulnerability_type,
                status=ProbeStatus.FAILED,
                reasoning="",
                error="boom",
            )
        return Finding(
            probe_id=probe.id,
            vulnerability_type=probe.vulnerability_type,
            score=score,
            severity=Severity.from_score(score),
            reasoning="r",
        )

    return run


def test_audit_runs_all_probes_in_order_and_reports_progress() -> None:
    seen: list[str] = []
    report = run_audit(
        fake_runner({"prompt_injection": 7, "hallucination": 3, "data_leakage": 10}),
        on_progress=lambda node, finding: seen.append(node),
    )
    assert seen == [p.id for p in ALL_PROBES]
    assert [f.probe_id for f in report.findings] == seen
    assert report.risk_score == 10
    assert report.overall_severity is Severity.CRITICAL
    assert report.started_at <= report.finished_at


def test_audit_survives_failed_probe() -> None:
    report = run_audit(
        fake_runner({"prompt_injection": 2, "hallucination": None, "data_leakage": 1})
    )
    assert report.probes_failed == 1
    assert report.risk_score == 2


def test_graph_rejects_empty_probe_list() -> None:
    with pytest.raises(ValueError, match="At least one probe"):
        build_audit_graph(fake_runner({}), probes=[])
