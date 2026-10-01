"""FastAPI service exposing the target assistant and the audit job runner.

Run with: uvicorn ragsentry.api.app:create_app --factory
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from ragsentry import __version__
from ragsentry.api.jobs import AuditAlreadyRunningError, AuditFn, AuditJob, JobManager
from ragsentry.auditor.models import AuditReport, Finding
from ragsentry.auditor.probes import Probe
from ragsentry.config import MissingApiKeyError, Settings, get_settings
from ragsentry.target.pipeline import TargetUnavailableError, VulnerableRAG, index_exists

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    groq_configured: bool
    index_ready: bool


class QueryRequest(BaseModel):
    prompt: str = Field(..., min_length=1)

    @field_validator("prompt")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Prompt must not be blank.")
        return value


class QueryResponse(BaseModel):
    response: str
    sources: list[str]


def default_audit_fn(target: VulnerableRAG, settings: Settings) -> AuditFn:
    def audit(probes: Sequence[Probe], on_progress: Callable[[str, Finding], None]) -> AuditReport:
        # Imported lazily so the API starts quickly and tests need no LLM stack.
        from ragsentry.auditor.crew import CrewProbeRunner
        from ragsentry.auditor.graph import run_audit

        return run_audit(CrewProbeRunner(target, settings), probes, on_progress)

    return audit


def create_app(
    settings: Settings | None = None,
    target: VulnerableRAG | None = None,
    audit_fn: AuditFn | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s: %(message)s")
    target = target or VulnerableRAG(settings)
    jobs = JobManager(audit_fn or default_audit_fn(target, settings))

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        jobs.shutdown()

    app = FastAPI(
        title="RagSentry API",
        description="Run multi-agent security audits against a deliberately vulnerable RAG assistant.",
        version=__version__,
        lifespan=lifespan,
    )

    def require_key() -> None:
        if not settings.groq_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GROQ_API_KEY is not configured on the server. Add it to .env and restart.",
            )

    @app.get("/api/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(
            version=__version__,
            groq_configured=settings.groq_configured,
            index_ready=index_exists(settings),
        )

    @app.post("/api/target/query", response_model=QueryResponse, tags=["target"])
    def query_target(req: QueryRequest) -> QueryResponse:
        """Send one prompt to the vulnerable target assistant."""
        require_key()
        if len(req.prompt) > settings.max_prompt_chars:
            raise HTTPException(
                status_code=422,
                detail=f"Prompt exceeds {settings.max_prompt_chars} characters.",
            )
        try:
            result = target.query(req.prompt)
        except MissingApiKeyError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
        except TargetUnavailableError as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, f"The target assistant failed: {exc}"
            ) from exc
        return QueryResponse(response=result.answer, sources=result.sources)

    @app.post(
        "/api/audits",
        response_model=AuditJob,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["audits"],
    )
    def start_audit() -> AuditJob:
        """Start a full audit in the background. Poll `GET /api/audits/{id}` for progress."""
        require_key()
        try:
            return jobs.submit()
        except AuditAlreadyRunningError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"message": "An audit is already running.", "job_id": exc.job_id},
            ) from exc

    @app.get("/api/audits/{job_id}", response_model=AuditJob, tags=["audits"])
    def get_audit(job_id: str) -> AuditJob:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found.")
        return job

    return app
