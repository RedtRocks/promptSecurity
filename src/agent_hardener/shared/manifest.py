"""Reproducibility manifest emission.

A `run_manifest.json` captures model identity, configuration, and pipeline-health
metrics so that paper runs are reproducible and auditable. Anything that affects
the headline numbers should appear here.
"""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path
from typing import Any

from agent_hardener.shared.settings import Settings


def write_run_manifest(
    *,
    output_dir: Path,
    settings: Settings,
    tool_name: str,
    command: str,
    attack_records: list[Any],
    adversarial_prompts: list[Any],
    elapsed_s: float,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Write run_manifest.json next to the report. Returns the written path."""
    try:
        import litellm
        litellm_version = getattr(litellm, "__version__", "unknown")
    except Exception:
        litellm_version = "unknown"

    n_fallback = sum(1 for p in adversarial_prompts if getattr(p, "is_fallback", False))
    n_refused = sum(1 for r in attack_records if getattr(r, "refusal_occurred", False))

    primary_provider = settings.default_model.split("/")[0] if "/" in settings.default_model else ""
    grader_provider = (
        settings.grader_model.split("/")[0]
        if settings.grader_model and "/" in settings.grader_model
        else primary_provider
    )

    manifest: dict[str, Any] = {
        "schema": "agent-hardener-manifest/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "command": command,
        "tool_name": tool_name,
        "elapsed_seconds": round(elapsed_s, 2),
        "models": {
            "default_model": settings.default_model,
            "grader_model": settings.grader_model or "(same as default — self-grading)",
            "same_family_grader": grader_provider == primary_provider,
            "ollama_base_url": settings.ollama_base_url,
        },
        "pipeline_settings": {
            "max_iterations": settings.max_iterations,
            "attack_parallelism": settings.attack_parallelism,
            "attack_success_threshold": settings.attack_success_threshold,
            "hardening_rounds": settings.hardening_rounds,
            "hardening_target_success_rate": settings.hardening_target_success_rate,
            "enable_signature_memory": settings.enable_signature_memory,
            "baseline_attacks": settings.baseline_attacks,
            "n_repeats": settings.n_repeats,
            "enforce_prior_policy": settings.enforce_prior_policy,
        },
        "agent_endpoint": settings.agent_endpoint,
        "pipeline_health": {
            "n_prompts_generated": len(adversarial_prompts),
            "n_fallback_prompts": n_fallback,
            "fallback_rate": n_fallback / max(1, len(adversarial_prompts)),
            "n_attacks": len(attack_records),
            "n_refusals": n_refused,
            "refusal_rate": n_refused / max(1, len(attack_records)),
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "litellm_version": litellm_version,
        },
    }

    if extra:
        manifest["extra"] = extra

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path
