"""Aggregate multiple run_manifest.json files into a paper-ready CSV.

Usage:
    python scripts/aggregate_runs.py output_dir1/ output_dir2/ ... \
        [--out runs_summary.csv]

Each directory is expected to contain a `run_manifest.json` (emitted by
agent-hardener analyze / harden) and optionally a `report.json`. The script:

  1. Reads every manifest, pulling tool name, model identity, settings, and
     pipeline-health metrics.
  2. If `report.json` is present, pulls aggregate attack metrics: per-record
     scores, success counts, and (if seed sweeps were used) per-seed variance.
  3. Emits one CSV row per (tool, run) with all columns flattened, ready for
     pivoting / plotting.

Dependency-free stdlib only — runs anywhere the project does.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any


CSV_COLUMNS = [
    "manifest_path",
    "command",
    "tool_name",
    "generated_at",
    "default_model",
    "grader_model",
    "same_family_grader",
    "max_iterations",
    "attack_success_threshold",
    "hardening_rounds",
    "n_repeats",
    "baseline_attacks",
    "enable_signature_memory",
    "enforce_prior_policy",
    "elapsed_seconds",
    "n_attacks",
    "n_refusals",
    "refusal_rate",
    "n_fallback_prompts",
    "fallback_rate",
    "n_successes",
    "success_rate",
    "mean_score",
    "score_stddev",
    "mean_seed_stddev",  # average within-record variance from seed sweeps
    "policy_fully_blocked",
    "policy_partially_mitigated",
    "policy_requiring_model_level",
    "policy_unmitigated",
    # Security/utility tradeoff — the headline research metric.
    "n_successful_attacks",
    "abr_defined",
    "attack_block_rate",
    "mitigation_rate",
    "benign_pass_rate",
    "over_block_rate",
    "utility_security_f1",
    "degenerate_deny_all",
]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not read {path}: {exc}", file=sys.stderr)
        return {}


def _stddev(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    mean = sum(xs) / len(xs)
    var = sum((x - mean) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(var)


def _row_from_dir(d: Path, success_threshold: float = 0.95) -> dict[str, Any] | None:
    manifest_path = d / "run_manifest.json"
    if not manifest_path.exists():
        print(f"WARN: no run_manifest.json in {d}", file=sys.stderr)
        return None

    manifest = _read_json(manifest_path)
    report_path = d / "report.json"
    report = _read_json(report_path) if report_path.exists() else {}

    # Pull settings the manifest already exposes.
    models = manifest.get("models", {})
    settings = manifest.get("pipeline_settings", {})
    health = manifest.get("pipeline_health", {})

    # Compute attack-level stats from the report (if present).
    records: list[dict] = report.get("stage1_attack_records", [])
    scores = [r.get("final_score", 0.0) for r in records]
    n_successes = sum(1 for s in scores if s > success_threshold)

    # Within-record variance across seeds (if seed sweeps were used).
    seed_stddevs = [
        _stddev(r.get("seed_scores", []))
        for r in records
        if r.get("seed_scores")
    ]
    mean_seed_stddev = sum(seed_stddevs) / len(seed_stddevs) if seed_stddevs else 0.0

    coverage = report.get("stage3_policy", {}).get("policy_coverage", {})
    su = report.get("security_utility", {})

    n_successful_attacks = su.get("n_successful_attacks", 0) or 0
    abr_defined = bool(n_successful_attacks)
    return {
        "manifest_path": str(manifest_path),
        "command": manifest.get("command", ""),
        "tool_name": manifest.get("tool_name", ""),
        "generated_at": manifest.get("generated_at", ""),
        "default_model": models.get("default_model", ""),
        "grader_model": models.get("grader_model", ""),
        "same_family_grader": models.get("same_family_grader", ""),
        "max_iterations": settings.get("max_iterations", ""),
        "attack_success_threshold": settings.get("attack_success_threshold", ""),
        "hardening_rounds": settings.get("hardening_rounds", ""),
        "n_repeats": settings.get("n_repeats", 1),
        "baseline_attacks": settings.get("baseline_attacks", "llm"),
        "enable_signature_memory": settings.get("enable_signature_memory", False),
        "enforce_prior_policy": settings.get("enforce_prior_policy", False),
        "elapsed_seconds": manifest.get("elapsed_seconds", ""),
        "n_attacks": health.get("n_attacks", len(records)),
        "n_refusals": health.get("n_refusals", ""),
        "refusal_rate": round(health.get("refusal_rate", 0.0), 4),
        "n_fallback_prompts": health.get("n_fallback_prompts", ""),
        "fallback_rate": round(health.get("fallback_rate", 0.0), 4),
        "n_successes": n_successes,
        "success_rate": round(n_successes / max(1, len(records)), 4),
        "mean_score": round(sum(scores) / max(1, len(scores)), 4),
        "score_stddev": round(_stddev(scores), 4),
        "mean_seed_stddev": round(mean_seed_stddev, 4),
        "policy_fully_blocked": coverage.get("attacks_fully_blocked_by_policy", ""),
        "policy_partially_mitigated": coverage.get("attacks_partially_mitigated", ""),
        "policy_requiring_model_level": coverage.get("attacks_requiring_model_level_defense", ""),
        "policy_unmitigated": coverage.get("unmitigated_attacks", ""),
        "n_successful_attacks": n_successful_attacks,
        "abr_defined": abr_defined,
        # ABR/mitigation/F1 are ratios over SUCCESSFUL attacks. With no successful
        # attack the denominator is empty, so they are UNDEFINED, not zero. The
        # verifier reports 0.0 there; emitting that verbatim would let a tool the
        # agent simply refused drag the corpus mean down as if the policy had
        # failed. Blank means "no data", and _aggregate_by_tool skips blanks.
        "attack_block_rate": su.get("attack_block_rate", "") if abr_defined else "",
        "mitigation_rate": su.get("mitigation_rate", "") if abr_defined else "",
        "benign_pass_rate": su.get("benign_pass_rate", ""),
        "over_block_rate": su.get("over_block_rate", ""),
        "utility_security_f1": su.get("utility_security_f1", "") if abr_defined else "",
        "degenerate_deny_all": su.get("degenerate_deny_all", ""),
    }


# Numeric metrics that get a mean±std across independent runs of the same tool.
_BY_TOOL_METRICS = [
    "attack_block_rate",
    "mitigation_rate",
    "benign_pass_rate",
    "over_block_rate",
    "utility_security_f1",
    "success_rate",
]


def _aggregate_by_tool(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group per-run rows by tool_name and compute mean±std per metric.

    This is the statistical-rigor view for the paper: run each tool N independent
    times, then read off the mean and standard deviation of ABR / mitigation /
    BPR / F1 across the N runs, rather than quoting a single noisy point estimate.
    """
    by_tool: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_tool.setdefault(row.get("tool_name", "?"), []).append(row)

    out: list[dict[str, Any]] = []
    for tool, tool_rows in sorted(by_tool.items()):
        agg: dict[str, Any] = {"tool_name": tool, "n_runs": len(tool_rows)}
        for metric in _BY_TOOL_METRICS:
            vals = [
                float(r[metric])
                for r in tool_rows
                if r.get(metric) not in ("", None)
            ]
            if vals:
                mean = sum(vals) / len(vals)
                agg[f"{metric}_mean"] = round(mean, 4)
                agg[f"{metric}_std"] = round(_stddev(vals), 4)
            else:
                agg[f"{metric}_mean"] = ""
                agg[f"{metric}_std"] = ""
        out.append(agg)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_dirs", nargs="+", type=Path, help="Directories produced by agent-hardener")
    p.add_argument("--out", type=Path, default=Path("runs_summary.csv"), help="Output CSV path")
    p.add_argument(
        "--by-tool", type=Path, default=None,
        help="Also write a per-tool mean±std CSV aggregating independent runs of each tool",
    )
    p.add_argument(
        "--success-threshold", type=float, default=0.95,
        help="Score above which an attack is counted as success when computing rates",
    )
    args = p.parse_args()

    rows: list[dict[str, Any]] = []
    for d in args.run_dirs:
        if not d.is_dir():
            print(f"WARN: not a directory: {d}", file=sys.stderr)
            continue
        row = _row_from_dir(d, success_threshold=args.success_threshold)
        if row is not None:
            rows.append(row)

    if not rows:
        print("ERROR: no usable run directories", file=sys.stderr)
        return 1

    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {args.out}")

    if args.by_tool is not None:
        by_tool_rows = _aggregate_by_tool(rows)
        fieldnames = ["tool_name", "n_runs"] + [
            f"{m}_{stat}" for m in _BY_TOOL_METRICS for stat in ("mean", "std")
        ]
        with args.by_tool.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(by_tool_rows)
        print(f"Wrote {len(by_tool_rows)} per-tool rows to {args.by_tool}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
