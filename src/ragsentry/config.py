"""Application settings, loaded from environment variables and an optional `.env` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="RAGSENTRY_",
        extra="ignore",
    )

    # The Groq key keeps its conventional, unprefixed name.
    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GROQ_API_KEY", "RAGSENTRY_GROQ_API_KEY"),
    )

    auditor_model: str = "groq/llama-3.3-70b-versatile"
    """LiteLLM-style model id used by the auditor agents."""

    target_model: str = "llama-3.3-70b-versatile"
    """Groq model id used by the vulnerable target assistant."""

    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    index_dir: Path = Path(".data/faiss_index")
    retriever_k: int = Field(default=2, ge=1, le=10)

    auditor_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    target_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    agent_max_iterations: int = Field(default=8, ge=1, le=50)
    """Upper bound on tool-use iterations per agent, so a confused agent cannot loop forever."""

    max_prompt_chars: int = Field(default=4000, ge=1)
    log_level: str = "INFO"

    @property
    def groq_configured(self) -> bool:
        return bool(self.groq_api_key and self.groq_api_key.get_secret_value().strip())

    def require_groq_key(self) -> str:
        if not self.groq_configured:
            raise MissingApiKeyError(
                "GROQ_API_KEY is not set. Add it to your environment or .env file."
            )
        assert self.groq_api_key is not None
        return self.groq_api_key.get_secret_value()


class MissingApiKeyError(RuntimeError):
    """Raised when an operation needs the Groq API key and none is configured."""


@lru_cache
def get_settings() -> Settings:
    return Settings()
