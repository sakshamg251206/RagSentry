"""In-process background job manager for audits.

Audits take minutes, so the API starts them in a worker thread and clients poll for
progress. State lives in memory: it is lost on restart and is not shared between
processes, which is appropriate for a single-instance tool like this one.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from ragsentry.auditor.models import AuditReport, Finding
from ragsentry.auditor.probes import ALL_PROBES, Probe

logger = logging.getLogger(__name__)

# Signature of the function that actually performs an audit.
AuditFn = Callable[[Sequence[Probe], Callable[[str, Finding], None]], AuditReport]


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ProbeProgress(BaseModel):
    probe_id: str
    vulnerability_type: str
    summary: str
    done: bool = False


class AuditJob(BaseModel):
    id: str
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    probes: list[ProbeProgress]
    report: AuditReport | None = None
    error: str | None = None

    @property
    def finished(self) -> bool:
        return self.status in (JobStatus.COMPLETED, JobStatus.FAILED)


class AuditAlreadyRunningError(RuntimeError):
    def __init__(self, job_id: str) -> None:
        super().__init__(f"Audit {job_id} is already running.")
        self.job_id = job_id


class JobManager:
    def __init__(
        self,
        audit_fn: AuditFn,
        probes: Sequence[Probe] = ALL_PROBES,
        max_history: int = 20,
    ) -> None:
        self._audit_fn = audit_fn
        self._probes = tuple(probes)
        self._max_history = max_history
        self._jobs: OrderedDict[str, AuditJob] = OrderedDict()
        self._lock = threading.Lock()
        # One worker: audits share a rate-limited LLM quota, so extra requests queue.
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")

    def submit(self) -> AuditJob:
        job = AuditJob(
            id=uuid.uuid4().hex,
            probes=[
                ProbeProgress(
                    probe_id=p.id, vulnerability_type=p.vulnerability_type, summary=p.summary
                )
                for p in self._probes
            ],
        )
        with self._lock:
            # Check and insert under one lock so concurrent requests cannot both start.
            for existing in self._jobs.values():
                if not existing.finished:
                    raise AuditAlreadyRunningError(existing.id)
            self._jobs[job.id] = job
            self._evict_old()
        self._executor.submit(self._run, job.id)
        return job.model_copy(deep=True)

    def get(self, job_id: str) -> AuditJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.model_copy(deep=True) if job else None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _evict_old(self) -> None:
        finished = [jid for jid, j in self._jobs.items() if j.finished]
        while len(self._jobs) > self._max_history and finished:
            self._jobs.pop(finished.pop(0))

    def _update(self, job_id: str, **changes: object) -> None:
        with self._lock:
            job = self._jobs[job_id]
            self._jobs[job_id] = job.model_copy(update=changes)

    def _mark_probe_done(self, job_id: str, probe_id: str, _: Finding) -> None:
        with self._lock:
            for probe in self._jobs[job_id].probes:
                if probe.probe_id == probe_id:
                    probe.done = True

    def _run(self, job_id: str) -> None:
        self._update(job_id, status=JobStatus.RUNNING)
        try:
            report = self._audit_fn(
                self._probes, lambda pid, f: self._mark_probe_done(job_id, pid, f)
            )
        except Exception as exc:
            logger.exception("Audit %s failed", job_id)
            self._update(
                job_id,
                status=JobStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
                finished_at=datetime.now(timezone.utc),
            )
            return
        self._update(
            job_id,
            status=JobStatus.COMPLETED,
            report=report,
            finished_at=datetime.now(timezone.utc),
        )
