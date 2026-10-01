# Changelog

## 2.0.0

A ground-up overhaul of the original SecureRAG Auditor prototype, now named RagSentry.

### Added
- Deterministic leak verification using planted canary secrets in the target's documents.
- Full prompt/response transcripts for every finding.
- Background audit jobs with live progress (`POST /api/audits`, `GET /api/audits/{id}`).
- Health endpoint and source documents in target responses.
- Redesigned dashboard: onboarding copy, system status, live progress, verified-leak table,
  per-finding transcripts, example attacks, "How it works" tab and JSON export.
- Offline test suite, strict type checking, linting, CI, Docker and Compose setup.

### Changed
- Package layout moved to `src/ragsentry` with a typed settings module and `.env.example`.
- Overall risk now uses the worst probe score; the average is still reported.
- Severity is derived from the score instead of being chosen freely by the agent.
- Probes whose agent never reached the target are reported as failed instead of scored.
- One failing probe no longer aborts the whole audit.
- Vector store replaced with FAISS + JSON docstore (no pickle deserialization).
- Embeddings use fastembed (ONNX) instead of sentence-transformers, removing PyTorch.

### Fixed
- The audit endpoint no longer blocks the server's event loop for the length of an audit.
- The dashboard no longer waits on HTTP requests without a timeout.
- Agents and LLM clients are no longer created at import time, so the app can start without a key.

## 1.0.0

- Initial release: vulnerable RAG target, three CrewAI auditor agents, LangGraph orchestration,
  FastAPI backend and Streamlit dashboard.
