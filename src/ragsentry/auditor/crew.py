"""CrewAI integration: turns a `Probe` into an agent, runs it, and returns a `Finding`."""

from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, Field, PrivateAttr

from ragsentry.auditor.models import (
    AgentAssessment,
    Finding,
    ProbeStatus,
    Severity,
    TargetInteraction,
)
from ragsentry.auditor.probes import TOOL_NAME, Probe
from ragsentry.auditor.scoring import apply_evidence
from ragsentry.config import Settings, get_settings
from ragsentry.target.pipeline import TargetResponse, TargetUnavailableError

if TYPE_CHECKING:
    from crewai.tools import BaseTool

logger = logging.getLogger(__name__)


class Target(Protocol):
    def query(self, question: str) -> TargetResponse: ...


class InteractionLog:
    """Thread-safe record of every prompt an agent sends to the target."""

    def __init__(self) -> None:
        self._items: list[TargetInteraction] = []
        self._lock = threading.Lock()

    def add(self, interaction: TargetInteraction) -> None:
        with self._lock:
            self._items.append(interaction)

    def snapshot(self) -> list[TargetInteraction]:
        with self._lock:
            return list(self._items)


def query_and_record(target: Target, log: InteractionLog, query: str) -> str:
    """Send one prompt to the target, record the exchange, and return the reply text."""
    try:
        reply = target.query(query).answer
    except TargetUnavailableError as exc:
        log.add(TargetInteraction(prompt=query, response=str(exc), error=True))
        return f"ERROR: the target did not respond ({exc})."
    log.add(TargetInteraction(prompt=query, response=reply))
    return reply


class _TargetQueryInput(BaseModel):
    query: str = Field(..., description="The exact prompt to send to the target assistant.")


def make_target_tool(target: Target, log: InteractionLog) -> BaseTool:
    from crewai.tools import BaseTool

    class TargetQueryTool(BaseTool):
        name: str = TOOL_NAME
        description: str = (
            "Send exactly one prompt to the target RAG assistant under audit and return its "
            "reply verbatim."
        )
        args_schema: type[BaseModel] = _TargetQueryInput
        _target: Any = PrivateAttr()
        _log: Any = PrivateAttr()

        def __init__(self, **data: Any) -> None:
            super().__init__(**data)
            self._target = target
            self._log = log

        def _run(self, query: str) -> str:
            return query_and_record(self._target, self._log, query)

    return TargetQueryTool()


def _failed(probe: Probe, message: str, interactions: list[TargetInteraction]) -> Finding:
    return Finding(
        probe_id=probe.id,
        vulnerability_type=probe.vulnerability_type,
        status=ProbeStatus.FAILED,
        reasoning="This probe did not complete, so it is excluded from the score.",
        error=message,
        interactions=interactions,
    )


def finding_from_assessment(
    probe: Probe, assessment: AgentAssessment | None, interactions: list[TargetInteraction]
) -> Finding:
    """Validate an agent's output against what actually happened, then score it."""
    if not interactions:
        return _failed(probe, "The agent never queried the target.", interactions)
    if all(i.error for i in interactions):
        return _failed(
            probe, f"The target failed to respond: {interactions[-1].response}", interactions
        )
    if assessment is None:
        return _failed(probe, "The agent did not return a structured assessment.", interactions)

    finding = Finding(
        probe_id=probe.id,
        vulnerability_type=probe.vulnerability_type,
        score=assessment.score,
        severity=Severity.from_score(assessment.score),
        reasoning=assessment.reasoning,
        recommended_fix=assessment.recommended_fix,
        successful_attack_prompt=assessment.successful_attack_prompt or None,
        interactions=interactions,
    )
    return apply_evidence(finding)


class CrewProbeRunner:
    """Runs one probe as a single-agent CrewAI crew against the given target."""

    def __init__(self, target: Target, settings: Settings | None = None) -> None:
        self._target = target
        self._settings = settings or get_settings()

    def __call__(self, probe: Probe) -> Finding:
        log = InteractionLog()
        try:
            assessment = self._kickoff(probe, log)
        except Exception as exc:  # provider errors, rate limits, malformed output
            logger.exception("Probe %s failed", probe.id)
            return _failed(probe, f"{type(exc).__name__}: {exc}", log.snapshot())
        return finding_from_assessment(probe, assessment, log.snapshot())

    def _kickoff(self, probe: Probe, log: InteractionLog) -> AgentAssessment | None:
        # Audits run headless inside the API: opt out of CrewAI's anonymous telemetry and
        # its interactive trace-viewing prompt unless the operator explicitly enables them.
        os.environ.setdefault("OTEL_SDK_DISABLED", "true")
        os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
        from crewai import LLM, Agent, Crew, Process, Task

        llm = LLM(
            model=self._settings.auditor_model,
            temperature=self._settings.auditor_temperature,
            api_key=self._settings.require_groq_key(),
        )
        agent = Agent(
            role=probe.role,
            goal=probe.goal,
            backstory=probe.backstory,
            tools=[make_target_tool(self._target, log)],
            llm=llm,
            allow_delegation=False,
            max_iter=self._settings.agent_max_iterations,
            verbose=False,
        )
        task = Task(
            description=probe.instructions,
            expected_output=probe.expected_output,
            agent=agent,
            output_pydantic=AgentAssessment,
        )
        result = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            tracing=False,
            verbose=False,
        ).kickoff()
        parsed = getattr(result, "pydantic", None)
        return parsed if isinstance(parsed, AgentAssessment) else None
