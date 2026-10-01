"""LangGraph workflow that runs each probe in turn and compiles the final report."""

from __future__ import annotations

import logging
import operator
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Annotated, Any

from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from ragsentry.auditor.models import AuditReport, Finding
from ragsentry.auditor.probes import ALL_PROBES, Probe
from ragsentry.auditor.scoring import build_report

logger = logging.getLogger(__name__)

ProbeRunner = Callable[[Probe], Finding]
ProgressCallback = Callable[[str, Finding], None]

REPORT_NODE = "compile_report"


class AuditState(TypedDict):
    started_at: datetime
    # Each probe node returns a one-item list; the reducer appends it.
    findings: Annotated[list[Finding], operator.add]
    report: AuditReport | None


class _ProbeNode:
    """Graph node that runs a single probe and contributes its finding to the state."""

    def __init__(self, probe: Probe, run_probe: ProbeRunner) -> None:
        self._probe = probe
        self._run_probe = run_probe

    def __call__(self, state: AuditState) -> dict[str, Any]:
        probe = self._probe
        logger.info("Running probe: %s", probe.vulnerability_type)
        finding = self._run_probe(probe)
        logger.info(
            "Probe %s finished: status=%s score=%s",
            probe.id,
            finding.status.value,
            finding.score,
        )
        return {"findings": [finding]}


def _compile_report(state: AuditState) -> dict[str, Any]:
    report = build_report(state["findings"], state["started_at"], datetime.now(timezone.utc))
    return {"report": report}


def build_audit_graph(run_probe: ProbeRunner, probes: Sequence[Probe] = ALL_PROBES) -> Any:
    if not probes:
        raise ValueError("At least one probe is required.")
    workflow = StateGraph(AuditState)
    previous = START
    for probe in probes:
        workflow.add_node(probe.id, _ProbeNode(probe, run_probe))
        workflow.add_edge(previous, probe.id)
        previous = probe.id
    workflow.add_node(REPORT_NODE, _compile_report)
    workflow.add_edge(previous, REPORT_NODE)
    workflow.add_edge(REPORT_NODE, END)
    return workflow.compile()


def run_audit(
    run_probe: ProbeRunner,
    probes: Sequence[Probe] = ALL_PROBES,
    on_progress: ProgressCallback | None = None,
) -> AuditReport:
    """Run every probe sequentially and return the compiled report.

    Probes run one after another rather than in parallel on purpose: they share one
    rate-limited LLM provider, and sequential runs keep the target's logs readable.
    """
    graph = build_audit_graph(run_probe, probes)
    initial: AuditState = {
        "started_at": datetime.now(timezone.utc),
        "findings": [],
        "report": None,
    }
    report: AuditReport | None = None
    for update in graph.stream(initial, stream_mode="updates"):
        for node, delta in update.items():
            if node == REPORT_NODE:
                report = delta["report"]
            elif on_progress is not None:
                on_progress(node, delta["findings"][0])
    if report is None:  # pragma: no cover - the graph always ends at the report node
        raise RuntimeError("Audit graph finished without producing a report.")
    return report
