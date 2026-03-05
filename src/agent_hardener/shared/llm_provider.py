"""LiteLLM-backed LLM provider abstraction.

All pipeline stages call this module.  No stage imports litellm directly.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import litellm
from litellm import Router

from agent_hardener.shared.settings import Settings


class LLMProvider:
    """Thin, stateless wrapper around LiteLLM that reads config from Settings."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._configure_env(settings)
        # Build a Router for automatic retry/fallback
        self._router = self._build_router(settings)

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _configure_env(s: Settings) -> None:
        """Push API keys into env vars so LiteLLM picks them up automatically."""
        _set_if_nonempty("OPENAI_API_KEY", s.openai_api_key)
        _set_if_nonempty("ANTHROPIC_API_KEY", s.anthropic_api_key)
        _set_if_nonempty("AZURE_API_KEY", s.azure_api_key)
        _set_if_nonempty("AZURE_API_BASE", s.azure_api_base)
        _set_if_nonempty("AZURE_API_VERSION", s.azure_api_version)
        if s.ollama_base_url:
            litellm.api_base = s.ollama_base_url

    @staticmethod
    def _build_router(s: Settings) -> Router:
        """Create a LiteLLM Router with the configured model as the primary deployment."""
        model_list = [
            {
                "model_name": "primary",
                "litellm_params": {"model": s.default_model},
            }
        ]
        # If a grader model is specified, add it as a named deployment
        if s.grader_model and s.grader_model != s.default_model:
            model_list.append(
                {
                    "model_name": "grader",
                    "litellm_params": {"model": s.grader_model},
                }
            )
        return Router(model_list=model_list, num_retries=3, retry_after=5)

    # ── public API ────────────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model_alias: str = "primary",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        response_format: Optional[dict[str, Any]] = None,
    ) -> str:
        """Call the LLM and return the assistant's text content.

        Args:
            messages: OpenAI-format message list.
            model_alias: 'primary' or 'grader' (as registered in the Router).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens for the completion.
            response_format: Optional dict, e.g. {"type": "json_object"}.

        Returns:
            The assistant message content as a plain string.
        """
        kwargs: dict[str, Any] = {
            "model": model_alias,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format:
            kwargs["response_format"] = response_format

        # Router handles retries and provider failover automatically
        response = self._router.completion(**kwargs)
        content = response.choices[0].message.content
        return content.strip() if content else ""

    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        model_alias: str = "primary",
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> str:
        """Like chat(), but enforces JSON output mode where the provider supports it."""
        return self.chat(
            messages,
            model_alias=model_alias,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )


def _set_if_nonempty(key: str, value: str) -> None:
    if value:
        os.environ[key] = value
