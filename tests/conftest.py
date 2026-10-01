from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ragsentry.config import Settings


class HashEmbedder:
    """Deterministic bag-of-words embedder, so retrieval works offline in tests."""

    dim = 64

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for token in re.findall(r"[a-z0-9]+", text.lower()):
                digest = hashlib.md5(token.encode(), usedforsecurity=False).digest()
                out[row, digest[0] % self.dim] += 1.0
        return out


class EchoLLM:
    """Stands in for the target LLM by repeating the retrieved context, like a leaky model."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def invoke(self, prompt: str) -> Any:
        self.prompts.append(prompt)
        context = prompt.split("Context:")[1].split("Question:")[0].strip()

        class Message:
            content = f"Sure! Here is what I found: {context}"

        return Message()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        GROQ_API_KEY="test-key",
        index_dir=tmp_path / "index",
    )


@pytest.fixture
def embedder() -> HashEmbedder:
    return HashEmbedder()
