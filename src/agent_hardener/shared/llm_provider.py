"""LiteLLM-backed LLM provider abstraction.

All pipeline stages call this module.  No stage imports litellm directly.
Includes model-specific optimizations for Qwen, Gemma, and other open-source models.
"""

from __future__ import annotations

import os
import subprocess
import shutil
from typing import Any, Optional

import litellm
from litellm import Router
import requests

from agent_hardener.shared.model_config import (
    detect_model_family,
    enhance_system_prompt_for_model,
    get_attack_prompt_suffix,
    get_model_parameters,
    get_refine_prompt_suffix,
    ModelFamily,
    ModelParameters,
)
from agent_hardener.shared.settings import Settings


class LLMProvider:
    """Thin, stateless wrapper around LiteLLM that reads config from Settings.
    
    Provides model-specific optimizations for temperature, token limits, and prompt
    engineering based on the detected model family (Qwen, Gemma, OpenAI, etc.).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._configure_env(settings)
        self._resolved_ollama_base_url = self._resolve_ollama_base_url()
        # Build a Router for automatic retry/fallback
        self._router = self._build_router(settings)
        
        # Detect model family and load optimized parameters
        self._primary_family = detect_model_family(settings.default_model)
        self._primary_params = get_model_parameters(settings.default_model)
        
        if settings.grader_model:
            self._grader_family = detect_model_family(settings.grader_model)
            self._grader_params = get_model_parameters(settings.grader_model)
        else:
            self._grader_family = self._primary_family
            self._grader_params = self._primary_params

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _configure_env(s: Settings) -> None:
        """Push API keys into env vars so LiteLLM picks them up automatically."""
        _set_if_nonempty("OPENAI_API_KEY", s.openai_api_key)
        _set_if_nonempty("ANTHROPIC_API_KEY", s.anthropic_api_key)
        _set_if_nonempty("AZURE_API_KEY", s.azure_api_key)
        _set_if_nonempty("AZURE_API_BASE", s.azure_api_base)
        _set_if_nonempty("AZURE_API_VERSION", s.azure_api_version)
        if _uses_ollama_model(s):
            # Keep LiteLLM pointed at the currently configured Ollama endpoint.
            # Direct Ollama calls below may still switch to localhost when a GPU server
            # exposes a local Ollama daemon.
            litellm.api_base = s.ollama_base_url.rstrip("/") if s.ollama_base_url else None
        else:
            # Prevent stale global api_base from affecting non-Ollama providers.
            litellm.api_base = None

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
        family = self._grader_family if model_alias == "grader" else self._primary_family
        if family in (ModelFamily.QWEN, ModelFamily.GEMMA, ModelFamily.LLAMA, ModelFamily.OLLAMA):
            model_name = (
                self._settings.grader_model
                if model_alias == "grader" and self._settings.grader_model
                else self._settings.default_model
            )
            return self._chat_ollama(
                model_name=model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format=response_format,
            )

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
        """Like chat(), but enforces JSON output mode where the provider supports it.
        
        For Ollama and other open-source models, we skip response_format since they
        don't support the OpenAI json_object mode. Instead, we rely on prompt engineering
        to guide them to output valid JSON.
        """
        family = self._grader_family if model_alias == "grader" else self._primary_family
        response_format = None
        if family in (ModelFamily.OPENAI, ModelFamily.ANTHROPIC):
            response_format = {"type": "json_object"}
        
        return self.chat(
            messages,
            model_alias=model_alias,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )

    def _chat_ollama(
        self,
        *,
        model_name: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        response_format: Optional[dict[str, Any]] = None,
    ) -> str:
        """Call the Ollama HTTP API directly so we can control think/format behavior."""
        base_url = self._resolved_ollama_base_url
        model = model_name.split("/", 1)[1] if "/" in model_name else model_name
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        if response_format and response_format.get("type") == "json_object":
            payload["format"] = "json"

        response = requests.post(f"{base_url}/api/chat", json=payload, timeout=300)
        response.raise_for_status()
        data = response.json()
        message = data.get("message") or {}
        content = message.get("content") or ""
        if content:
            return str(content).strip()

        # Some Ollama models may still place text elsewhere; preserve that for debugging.
        thinking = message.get("thinking") or ""
        if thinking and not content:
            return str(thinking).strip()

        return ""

    def _resolve_ollama_base_url(self) -> str:
        """Prefer a local Ollama daemon on CUDA-capable servers, otherwise use config.

        The local server is only selected when both of these are true:
        1. A CUDA GPU is visible to the machine.
        2. Ollama is responding on localhost:11434.

        If either condition fails, the provider keeps using the configured Ollama
        base URL so current API-backed behavior remains unchanged.
        """
        configured = (self._settings.ollama_base_url or "").rstrip("/")
        local = "http://localhost:11434"

        if self._cuda_gpu_available() and self._ollama_responds(local):
            return local

        if configured:
            return configured

        return local

    @staticmethod
    def _cuda_gpu_available() -> bool:
        """Return True when an NVIDIA GPU is visible via nvidia-smi."""
        nvidia_smi = shutil.which("nvidia-smi")
        if not nvidia_smi:
            return False

        try:
            result = subprocess.run(
                [nvidia_smi, "-L"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return False

        return result.returncode == 0 and "GPU" in (result.stdout or "")

    @staticmethod
    def _ollama_responds(base_url: str) -> bool:
        """Return True when an Ollama server answers on the given base URL."""
        try:
            response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=3)
            return response.ok
        except requests.RequestException:
            return False

    # ── Model-specific parameter accessors ────────────────────────────────────

    def get_attack_params(self) -> tuple[float, int]:
        """Get temperature and max_tokens for attack generation tasks.
        
        Returns:
            Tuple of (temperature, max_tokens) optimized for the primary model.
        """
        return self._primary_params.temperature_attack, self._primary_params.max_tokens_attack

    def get_refine_params(self) -> tuple[float, int]:
        """Get temperature and max_tokens for prompt refinement tasks.
        
        Returns:
            Tuple of (temperature, max_tokens) optimized for the primary model.
        """
        return self._primary_params.temperature_refine, self._primary_params.max_tokens_refine

    def get_grade_params(self) -> tuple[float, int]:
        """Get temperature and max_tokens for grading tasks.
        
        Returns:
            Tuple of (temperature, max_tokens) optimized for the grader model.
        """
        return self._grader_params.temperature_grade, self._grader_params.max_tokens_grade

    def get_profile_params(self) -> tuple[float, int]:
        """Get temperature and max_tokens for tool profiling tasks.
        
        Returns:
            Tuple of (temperature, max_tokens) optimized for the primary model.
        """
        # Profiling should be deterministic like grading, so use lower temperature
        return 0.1, self._primary_params.max_tokens_profile

    def enhance_system_prompt(self, base_system: str) -> str:
        """Add model-specific instructions to system prompts.
        
        Args:
            base_system: Original system prompt text.
        
        Returns:
            Enhanced system prompt with model-specific formatting instructions.
        """
        return enhance_system_prompt_for_model(base_system, self._primary_family)

    def get_attack_prompt_suffix(self) -> str:
        """Get model-specific guidance for attack generation.
        
        Returns:
            Additional prompt text optimized for the primary model.
        """
        return get_attack_prompt_suffix(self._primary_family)

    def get_refine_prompt_suffix(self) -> str:
        """Get model-specific guidance for prompt refinement.
        
        Returns:
            Additional prompt text optimized for the primary model.
        """
        return get_refine_prompt_suffix(self._primary_family)

    def get_model_family(self) -> ModelFamily:
        """Return the detected model family of the primary model.
        
        Returns:
            ModelFamily enum value.
        """
        return self._primary_family


def _set_if_nonempty(key: str, value: str) -> None:
    if value:
        os.environ[key] = value


def _uses_ollama_model(settings: Settings) -> bool:
    """Return True when any configured model targets the Ollama provider."""
    models = [settings.default_model, settings.grader_model]
    return any(m and m.lower().startswith("ollama/") for m in models)
