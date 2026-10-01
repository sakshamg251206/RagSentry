from __future__ import annotations

import json

import pytest

from ragsentry.config import MissingApiKeyError, Settings
from ragsentry.target.documents import CANARIES, SEED_DOCUMENTS
from ragsentry.target.pipeline import (
    DOCSTORE_FILE,
    TargetUnavailableError,
    VectorIndex,
    VulnerableRAG,
    build_index,
    index_exists,
    load_or_build_index,
)
from tests.conftest import EchoLLM, HashEmbedder


def test_every_canary_is_planted_in_its_source_document() -> None:
    by_source = {d.source: d.content for d in SEED_DOCUMENTS}
    for canary in CANARIES:
        content = by_source[canary.source]
        assert any(p.search(content) for p in canary.compiled()), canary.label


def test_build_save_and_load_round_trip(settings: Settings, embedder: HashEmbedder) -> None:
    assert not index_exists(settings)
    build_index(settings, embedder)
    assert index_exists(settings)

    loaded = VectorIndex.load(settings.index_dir, embedder)
    hits = loaded.search("AWS S3 backup bucket key", k=1)
    assert hits[0].source == "internal_wiki.txt"


def test_search_k_is_capped(settings: Settings, embedder: HashEmbedder) -> None:
    index = build_index(settings, embedder)
    assert len(index.search("anything", k=50)) == len(SEED_DOCUMENTS)


def test_docstore_is_plain_json(settings: Settings, embedder: HashEmbedder) -> None:
    build_index(settings, embedder)
    payload = json.loads((settings.index_dir / DOCSTORE_FILE).read_text())
    assert payload["embedding_model"] == settings.embedding_model
    assert len(payload["documents"]) == len(SEED_DOCUMENTS)


def test_rebuilds_corrupt_index(settings: Settings, embedder: HashEmbedder) -> None:
    build_index(settings, embedder)
    (settings.index_dir / DOCSTORE_FILE).write_text("not json")
    index = load_or_build_index(settings, embedder)
    assert len(index.search("password", k=1)) == 1


def test_rebuilds_when_embedding_model_changes(settings: Settings, embedder: HashEmbedder) -> None:
    build_index(settings, embedder)
    changed = settings.model_copy(update={"embedding_model": "other/model"})
    assert load_or_build_index(changed, embedder).model == "other/model"


def test_query_returns_answer_and_sources(settings: Settings, embedder: HashEmbedder) -> None:
    llm = EchoLLM()
    rag = VulnerableRAG(settings, index=build_index(settings, embedder), llm=llm)
    result = rag.query("What is the production PostgreSQL superuser password?")
    assert "onboarding_guide.md" in result.sources
    assert "postgresAdmin!2024" in result.answer
    assert "Question:\nWhat is the production PostgreSQL" in llm.prompts[0]


def test_llm_failure_is_wrapped(settings: Settings, embedder: HashEmbedder) -> None:
    class BrokenLLM:
        def invoke(self, prompt: str) -> str:
            raise ConnectionError("network down")

    rag = VulnerableRAG(settings, index=build_index(settings, embedder), llm=BrokenLLM())
    with pytest.raises(TargetUnavailableError, match="network down"):
        rag.query("hi")


def test_missing_key_is_not_masked(settings: Settings, embedder: HashEmbedder) -> None:
    no_key = settings.model_copy(update={"groq_api_key": None})
    rag = VulnerableRAG(no_key, index=build_index(settings, embedder))
    with pytest.raises(MissingApiKeyError):
        rag.query("hi")
