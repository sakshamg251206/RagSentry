from __future__ import annotations

import pytest

from ragsentry.config import MissingApiKeyError, Settings


def test_reads_unprefixed_groq_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "abc")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.groq_configured
    assert settings.require_groq_key() == "abc"


def test_prefixed_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAGSENTRY_RETRIEVER_K", "4")
    monkeypatch.setenv("RAGSENTRY_TARGET_MODEL", "some-model")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.retriever_k == 4
    assert settings.target_model == "some-model"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_key(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    if value is not None:
        monkeypatch.setenv("GROQ_API_KEY", value)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert not settings.groq_configured
    with pytest.raises(MissingApiKeyError):
        settings.require_groq_key()


def test_key_is_not_exposed_in_repr() -> None:
    settings = Settings(_env_file=None, GROQ_API_KEY="super-secret")  # type: ignore[call-arg]
    assert "super-secret" not in repr(settings)
