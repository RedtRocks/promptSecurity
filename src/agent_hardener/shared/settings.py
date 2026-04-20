"""Pydantic-settings configuration. All fields can be overridden via environment
variables (UPPERCASE) or a YAML config file passed with --config."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM provider
    default_model: str = Field("openai/gpt-4o", description="LiteLLM model string")
    grader_model: str = Field("", description="Override model for LLM-as-judge")

    # API keys (read from env if not in config file)
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    anthropic_api_key: str = Field("", alias="ANTHROPIC_API_KEY")
    azure_api_key: str = Field("", alias="AZURE_API_KEY")
    azure_api_base: str = Field("")
    azure_api_version: str = Field("")
    ollama_base_url: str = Field("https://supervision-enemies-merchant-intend.trycloudflare.com")

    # Agent endpoint
    agent_endpoint: str = Field("https://supervision-enemies-merchant-intend.trycloudflare.com")
    agent_auth_token: str = Field("")
    agent_transport: str = Field("http")  # "http" | "stdio" | "sse"

    # Pipeline settings
    max_iterations: int = Field(6, ge=1, le=10)
    attack_parallelism: int = Field(2, ge=1, le=8)
    attack_success_threshold: float = Field(0.95, ge=0.0, le=1.0)
    hardening_rounds: int = Field(3, ge=1, le=10)
    hardening_target_success_rate: float = Field(0.0, ge=0.0, le=1.0)

    # Output
    output_dir: Path = Field(Path("./hardener_output"))

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "Settings":
        """Load settings from a YAML file, merging with environment variables."""
        import yaml  # lazy import

        with open(yaml_path) as f:
            data = yaml.safe_load(f) or {}

        # Strip empty strings so env vars can override cleanly
        cleaned = {k: v for k, v in data.items() if v != "" and v is not None}
        return cls(**cleaned)
