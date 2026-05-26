"""Tests for the helper scripts in scripts/."""

from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_script(name: str):
    """Import a top-level script as a module."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCohenKappa:
    def test_perfect_agreement(self):
        ck = _load_script("cohen_kappa")
        kappa, diag = ck.cohen_kappa(["a", "b", "c", "a"], ["a", "b", "c", "a"])
        assert kappa == pytest.approx(1.0)
        assert diag["percent_agreement"] == 1.0

    def test_chance_agreement_gives_zero(self):
        # 50/50 distribution where both raters use a/b independently and agree
        # at chance rate. p_o ≈ p_e → kappa ≈ 0.
        ck = _load_script("cohen_kappa")
        a = ["a", "a", "b", "b", "a", "a", "b", "b"]
        b = ["a", "b", "a", "b", "a", "b", "a", "b"]
        kappa, _ = ck.cohen_kappa(a, b)
        assert -0.5 <= kappa <= 0.5  # close to zero

    def test_total_disagreement_negative(self):
        ck = _load_script("cohen_kappa")
        kappa, _ = ck.cohen_kappa(["a", "b", "a", "b"], ["b", "a", "b", "a"])
        assert kappa < 0

    def test_length_mismatch_raises(self):
        ck = _load_script("cohen_kappa")
        with pytest.raises(ValueError, match="Mismatched"):
            ck.cohen_kappa(["a", "b"], ["a"])

    def test_bootstrap_ci_runs(self):
        ck = _load_script("cohen_kappa")
        a = ["success", "fail"] * 10
        b = ["success", "fail"] * 10  # perfect agreement
        mean, lo, hi = ck.bootstrap_kappa_ci(a, b, n_boot=50, seed=1)
        assert mean == pytest.approx(1.0)
        assert lo <= mean <= hi

    def test_interpret_bands(self):
        ck = _load_script("cohen_kappa")
        assert ck._interpret(-0.1) == "worse than chance"
        assert ck._interpret(0.10) == "slight"
        assert ck._interpret(0.30) == "fair"
        assert ck._interpret(0.50) == "moderate"
        assert ck._interpret(0.70) == "substantial"
        assert ck._interpret(0.85) == "almost perfect"

    def test_cli_end_to_end(self, tmp_path: Path):
        csv_path = tmp_path / "labels.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["record_id", "rater_a", "rater_b"])
            for i in range(20):
                label = "success" if i % 2 == 0 else "fail"
                w.writerow([f"ATK-{i:03d}", label, label])  # perfect agreement
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "cohen_kappa.py"),
             str(csv_path), "--col-a", "rater_a", "--col-b", "rater_b"],
            capture_output=True, text=True, check=True,
        )
        assert "Cohen's kappa:        1.0000" in result.stdout
        assert "almost perfect" in result.stdout


class TestAggregateRuns:
    def test_aggregates_a_minimal_run(self, tmp_path: Path):
        # Build a minimal run directory with manifest + report.
        run_dir = tmp_path / "run_a"
        run_dir.mkdir()
        manifest = {
            "schema": "agent-hardener-manifest/1",
            "command": "analyze",
            "tool_name": "read_file",
            "generated_at": "2026-05-26T00:00:00Z",
            "elapsed_seconds": 12.3,
            "models": {
                "default_model": "openai/gpt-4o",
                "grader_model": "anthropic/claude-3-5-sonnet-20241022",
                "same_family_grader": False,
                "ollama_base_url": "",
            },
            "pipeline_settings": {
                "max_iterations": 6,
                "attack_parallelism": 2,
                "attack_success_threshold": 0.95,
                "hardening_rounds": 3,
                "hardening_target_success_rate": 0.0,
                "enable_signature_memory": False,
                "n_repeats": 3,
                "baseline_attacks": "llm",
                "enforce_prior_policy": False,
            },
            "agent_endpoint": "http://localhost:8080/run",
            "pipeline_health": {
                "n_prompts_generated": 8,
                "n_fallback_prompts": 1,
                "fallback_rate": 0.125,
                "n_attacks": 8,
                "n_refusals": 2,
                "refusal_rate": 0.25,
            },
            "environment": {"python": "3.13.5", "platform": "Windows", "litellm_version": "1.40"},
        }
        report = {
            "stage1_attack_records": [
                {"record_id": "ATK-001-fraud", "final_score": 0.97, "seed_scores": [0.96, 0.97, 0.98]},
                {"record_id": "ATK-002-fraud", "final_score": 0.10, "seed_scores": [0.1, 0.1, 0.1]},
            ],
            "stage3_policy": {
                "policy_coverage": {
                    "attacks_fully_blocked_by_policy": 1,
                    "attacks_partially_mitigated": 0,
                    "attacks_requiring_model_level_defense": 0,
                    "unmitigated_attacks": 0,
                },
            },
        }
        (run_dir / "run_manifest.json").write_text(json.dumps(manifest))
        (run_dir / "report.json").write_text(json.dumps(report))

        out_csv = tmp_path / "summary.csv"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "aggregate_runs.py"),
             str(run_dir), "--out", str(out_csv)],
            capture_output=True, text=True, check=True,
        )
        assert out_csv.exists()
        with out_csv.open(encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        row = rows[0]
        assert row["tool_name"] == "read_file"
        assert row["same_family_grader"] == "False"
        assert row["n_repeats"] == "3"
        assert row["n_successes"] == "1"  # only one record above threshold
        assert float(row["mean_seed_stddev"]) > 0  # seed-sweep variance picked up
        assert row["policy_fully_blocked"] == "1"

    def test_missing_manifest_skipped(self, tmp_path: Path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        out_csv = tmp_path / "summary.csv"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "aggregate_runs.py"),
             str(empty_dir), "--out", str(out_csv)],
            capture_output=True, text=True,
        )
        assert result.returncode != 0  # no usable rows
