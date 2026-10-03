"""ThreatWeave configuration via pydantic-settings."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve project root (use current working directory, which is safe for Streamlit Cloud and local execution)
_PROJECT_ROOT = Path.cwd()


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # === Required ===
    groq_api_key: str = ""

    # === Local model / custom OpenAI-compatible endpoint ===
    openai_api_base: str = ""
    openai_api_key: str = ""

    # === Optional API Keys ===
    nvd_api_key: str = ""
    otx_api_key: str = ""
    maxmind_license_key: str = ""

    # === Qdrant Configuration ===
    qdrant_mode: Literal["memory", "persistent"] = "memory"
    qdrant_path: str = str(_PROJECT_ROOT / "data" / "qdrant")
    qdrant_collection_name: str = "attack_techniques"

    # === Model Configuration ===
    llm_model: str = "groq/llama-3.1-70b-versatile"
    llm_fallback_model: str = "groq/llama-3.1-8b-instant"
    embedding_model: str = "all-mpnet-base-v2"
    reranker_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    # === Paths ===
    attack_data_dir: str = str(_PROJECT_ROOT / "data" / "attack")
    attack_techniques_file: str = str(_PROJECT_ROOT / "data" / "attack" / "techniques.json")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance and push API keys to env."""
    settings = Settings()

    # Push API keys into os.environ so litellm can find them
    if settings.groq_api_key:
        os.environ.setdefault("GROQ_API_KEY", settings.groq_api_key)
    if settings.nvd_api_key:
        os.environ.setdefault("NVD_API_KEY", settings.nvd_api_key)
    if settings.otx_api_key:
        os.environ.setdefault("OTX_API_KEY", settings.otx_api_key)
    if settings.openai_api_base:
        os.environ["OPENAI_API_BASE"] = settings.openai_api_base
    if settings.openai_api_key:
        os.environ.setdefault("OPENAI_API_KEY", settings.openai_api_key)

    return settings

