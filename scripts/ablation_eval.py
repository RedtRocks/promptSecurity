"""Ablation study: what each pipeline component and each policy gate contributes.

Two experiments, one script:

``gates`` (offline, no LLM calls)
    Takes a finished run's ``report.json`` and replays its attacks and benign
    tasks through the policy with ONE gate switched off at a time
    (leave-one-out), plus a no-policy floor. A gate whose removal does not
    lower the block rate is not doing the blocking; this is also where a
    memorised rule (one that fires only on the exact attack it was written
    from) shows up, as an in-sample vs. held-out gap. It also attributes every
    blocked attack to the gate that stopped it first.

    Knockouts isolate one gate each:
      no_capability   capability denials never fire (patched check; flipping the
                      flags instead would also change which tools count as sinks)
      no_ifc001       reads never raise confidentiality taint and the session
                      starts LOW, so the high→low exfiltration gate cannot fire
      no_ifc002       policy no longer declares that untrusted input taints the
                      session, so the injection gate cannot fire
      no_rules        enforcement rules removed

``pipeline`` (live, costs agent + LLM calls)
    Runs ``agent-hardener analyze`` once per condition per repeat and tabulates
    attack success against the unguarded agent, grader health, and the policy
    metrics. Conditions:
      full             LLM attacker + iterative refinement
      no_refine        LLM attacker, P0 only (``--no-refine``)
      template_attacks deterministic templates, no LLM attacker
                       (``--baseline-attacks template``)
    Runs are sequential on purpose: parallel runs contend for the same model
    server and make latency-dependent behaviour noisy.

Usage:
    python scripts/ablation_eval.py gates hardener_output/read_file_heldout \\
        --benign-dir benign_tasks_recorded --out ablation_gates.json
    python scripts/ablation_eval.py pipeline --tool-file mcp_tools/read_file.yaml \\
        --config config.yaml --repeats 3 --heldout-eval --out-dir hardener_output/ablation
"""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, ContextManager, Optional
from unittest.mock import patch

import typer
from rich.console import Console
from rich.table import Table

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_hardener.shared.schemas import (  # noqa: E402
    AttackRecord,
    ConfidentialityLevel,
    SAMOSPolicy,
    TaintLevel,
)
from agent_hardener.verifier import (  # noqa: E402
    evaluate_security_utility,
    load_benign_suite,
    verify_all_records,
)

app = typer.Typer(add_completion=False, no_args_is_help=True)

# Windows consoles default to cp1252 when piped, which mangles table glyphs.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if callable(_reconfigure):
        try:
            _reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass
console = Console()


# ── Offline gate ablation ─────────────────────────────────────────────────────

def _no_ifc001(policy: SAMOSPolicy) -> SAMOSPolicy:
    p = policy.model_copy(deep=True)
    p.confidentiality_annotations.read_confidentiality = ConfidentialityLevel.LOW
    p.gateway_enforcement.tool_annotation.read_confidentiality = ConfidentialityLevel.LOW
    p.session_taint_rules.initial_session_taint = TaintLevel.LOW
    p.gateway_enforcement.session_initial_taint = TaintLevel.LOW
    return p


def _no_ifc002(policy: SAMOSPolicy) -> SAMOSPolicy:
    p = policy.model_copy(deep=True)
    p.session_taint_rules.untrusted_input_taints_session = False
    return p


def _no_rules(policy: SAMOSPolicy) -> SAMOSPolicy:
    p = policy.model_copy(deep=True)
    p.enforcement_rules = []
    return p


def _capability_gate_off() -> ContextManager[Any]:
    return patch("agent_hardener.verifier.replay.capability_is_denied", return_value=False)


# name -> (policy transform, context manager factory, description)
_CONDITIONS: list[tuple[str, Callable[[SAMOSPolicy], SAMOSPolicy], Callable[[], ContextManager[Any]], str]] = [
    ("full_policy", lambda p: p, nullcontext, "all gates on"),
    ("no_capability", lambda p: p, _capability_gate_off, "capability denials off"),
    ("no_ifc001", _no_ifc001, nullcontext, "confidentiality taint (IFC-001) off"),
    ("no_ifc002", _no_ifc002, nullcontext, "integrity taint (IFC-002) off"),
    ("no_rules", _no_rules, nullcontext, "enforcement rules removed"),
    ("no_policy", lambda p: _no_rules(_no_ifc002(_no_ifc001(p))), _capability_gate_off, "every gate off (floor)"),
]


def _load_run(run_dir: Path) -> tuple[SAMOSPolicy, list[AttackRecord], list[AttackRecord] | None, float, str]:
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    manifest_path = run_dir / "run_manifest.json"
    threshold = 0.8
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        threshold = float(manifest.get("pipeline_settings", {}).get("attack_success_threshold", threshold))
    policy = SAMOSPolicy.model_validate(report["stage3_policy"])
    records = [AttackRecord.model_validate(r) for r in report["stage1_attack_records"]]
    heldout = report.get("heldout_evaluation")
    heldout_records = (
        [AttackRecord.model_validate(r) for r in heldout["attack_records"]] if heldout else None
    )
    return policy, records, heldout_records, threshold, report["tool"]["name"]


def _blocking_gate(verdict: Any) -> str:
    """Which gate stopped this attack first (verdicts return at the first BLOCK)."""
    if verdict.final_status.value != "BLOCKED":
        return "not_blocked"
    if verdict.triggered_capability_denials:
        return "capability"
    if verdict.taint_violation:
        return "ifc001"
    if verdict.integrity_violation:
        return "ifc002"
    return "rule"


def gate_ablation(run_dir: Path, benign_dir: Optional[Path]) -> dict[str, Any]:
    """Leave-one-out gate ablation over one finished run. Pure replay, no LLM."""
    policy, records, heldout_records, threshold, tool_name = _load_run(run_dir)
    benign_suite = load_benign_suite(tool_name, benign_dir)

    rows: list[dict[str, Any]] = []
    for name, transform, ctx, description in _CONDITIONS:
        variant = transform(policy)
        with ctx():
            su = evaluate_security_utility(records, variant, benign_suite, threshold)
            ho = (
                evaluate_security_utility(heldout_records, variant, None, threshold)
                if heldout_records is not None else None
            )
        rows.append({
            "condition": name,
            "description": description,
            "in_sample_successful": su.n_successful_attacks,
            "in_sample_blocked": su.attacks_blocked,
            "in_sample_block_rate": su.attack_block_rate,
            "heldout_successful": ho.n_successful_attacks if ho else None,
            "heldout_blocked": ho.attacks_blocked if ho else None,
            "heldout_block_rate": ho.attack_block_rate if ho else None,
            "n_benign": su.n_benign_tasks,
            "benign_pass_rate": su.benign_pass_rate if su.n_benign_tasks else None,
            "f1_in_sample": su.utility_security_f1 if su.n_benign_tasks else None,
        })

    def _attribution(recs: list[AttackRecord]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in verify_all_records(recs, policy, threshold):
            if v.attack_succeeded:
                gate = _blocking_gate(v)
                counts[gate] = counts.get(gate, 0) + 1
        return dict(sorted(counts.items()))

    return {
        "run_dir": str(run_dir),
        "tool": tool_name,
        "success_threshold": threshold,
        "benign_suite_provenance": benign_suite.provenance if benign_suite else "none",
        "conditions": rows,
        # For each successful attack, the gate that blocked it first under the
        # full policy. A gate can matter in leave-one-out without appearing here
        # (it was a backup), and vice versa.
        "first_blocking_gate": {
            "in_sample": _attribution(records),
            "heldout": _attribution(heldout_records) if heldout_records is not None else None,
        },
    }


def _fmt_rate(n_blocked: Any, n: Any, rate: Any) -> str:
    if n is None:
        return "–"
    if not n:
        return "n/a (0 succeeded)"
    return f"{rate:.0%} ({n_blocked}/{n})"


@app.command()
def gates(
    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="A run's output dir (has report.json)."),
    benign_dir: Optional[Path] = typer.Option(None, "--benign-dir", help="Benign-suite dir used by the run."),
    out: Optional[Path] = typer.Option(None, "--out", help="Write the ablation JSON here."),
) -> None:
    """Leave-one-out gate ablation on a finished run (offline, deterministic)."""
    result = gate_ablation(run_dir, benign_dir)
    table = Table(title=f"Gate ablation · {result['tool']} · threshold {result['success_threshold']}")
    for col in ("Condition", "In-sample block", "Held-out block", "Benign pass", "F1 (in-sample)"):
        table.add_column(col)
    for r in result["conditions"]:
        table.add_row(
            r["condition"],
            _fmt_rate(r["in_sample_blocked"], r["in_sample_successful"], r["in_sample_block_rate"]),
            _fmt_rate(r["heldout_blocked"], r["heldout_successful"], r["heldout_block_rate"]),
            "–" if r["benign_pass_rate"] is None else f"{r['benign_pass_rate']:.0%} ({r['n_benign']})",
            "–" if r["f1_in_sample"] is None else f"{r['f1_in_sample']:.2f}",
        )
    console.print(table)
    console.print(f"First blocking gate: {result['first_blocking_gate']}")
    if out:
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote {out}[/]")


# ── Live pipeline ablation ────────────────────────────────────────────────────

_PIPELINE_CONDITIONS: dict[str, list[str]] = {
    "full": [],
    "no_refine": ["--no-refine"],
    "template_attacks": ["--baseline-attacks", "template"],
}


def summarize_run(run_dir: Path) -> dict[str, Any]:
    """Headline numbers for one analyze run, read from its report + manifest."""
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    threshold = float(manifest["pipeline_settings"]["attack_success_threshold"])
    records = report["stage1_attack_records"]
    health = manifest.get("pipeline_health", {})
    su = report.get("security_utility", {})
    ho = (report.get("heldout_evaluation") or {}).get("security_utility")
    n = len(records)
    n_success = sum(1 for r in records if r["final_score"] > threshold)
    parse = health.get("llm_parse_health", {})
    n_calls = sum(v["n_calls"] for v in parse.values())
    n_failed = sum(v["n_failed"] for v in parse.values())
    return {
        "n_attacks": n,
        "attack_success_rate": n_success / n if n else None,
        "mean_final_score": statistics.fmean(r["final_score"] for r in records) if n else None,
        "refusal_rate": health.get("refusal_rate"),
        "prompt_fallback_rate": health.get("fallback_rate"),
        "llm_judge_share": health.get("grade_sources", {}).get("llm_judge_share"),
        "llm_parse_failure_rate": (n_failed / n_calls) if n_calls else None,
        "in_sample_block_rate": su.get("attack_block_rate") if su.get("n_successful_attacks") else None,
        "heldout_block_rate": ho.get("attack_block_rate") if ho and ho.get("n_successful_attacks") else None,
        "benign_pass_rate": su.get("benign_pass_rate") if su.get("n_benign_tasks") else None,
        "elapsed_seconds": manifest.get("elapsed_seconds"),
    }


def _mean_sd(values: list[Any]) -> dict[str, Any]:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return {"mean": None, "sd": None, "n": 0}
    return {
        "mean": statistics.fmean(vals),
        "sd": statistics.stdev(vals) if len(vals) > 1 else None,
        "n": len(vals),
    }


@app.command()
def pipeline(
    tool_file: Path = typer.Option(..., "--tool-file", exists=True, dir_okay=False),
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False),
    out_dir: Path = typer.Option(Path("hardener_output/ablation"), "--out-dir"),
    repeats: int = typer.Option(1, "--repeats", min=1, max=20),
    conditions: str = typer.Option(
        ",".join(_PIPELINE_CONDITIONS), "--conditions",
        help=f"Comma-separated subset of: {', '.join(_PIPELINE_CONDITIONS)}",
    ),
    heldout_eval: bool = typer.Option(False, "--heldout-eval", help="Pass --heldout-eval to every run (~2x cost)."),
    skip_existing: bool = typer.Option(True, "--skip-existing/--rerun", help="Reuse runs that already have a report."),
) -> None:
    """Run the attack-side ablation live, then tabulate mean ± sd per condition."""
    chosen = [c.strip() for c in conditions.split(",") if c.strip()]
    unknown = [c for c in chosen if c not in _PIPELINE_CONDITIONS]
    if unknown:
        raise typer.BadParameter(f"Unknown condition(s): {unknown}")

    runs: dict[str, list[dict[str, Any]]] = {c: [] for c in chosen}
    # Interleave conditions within each repeat so model-server drift over the
    # session hits every condition equally instead of one block of runs.
    for rep in range(1, repeats + 1):
        for cond in chosen:
            run_dir = out_dir / cond / f"rep{rep}"
            if not (skip_existing and (run_dir / "report.json").exists()):
                cmd = [
                    sys.executable, "-m", "agent_hardener.cli", "analyze",
                    "--tool-file", str(tool_file), "--config", str(config),
                    "-o", str(run_dir), *_PIPELINE_CONDITIONS[cond],
                ] + (["--heldout-eval"] if heldout_eval else [])
                console.rule(f"[bold]{cond} · repeat {rep}/{repeats}")
                started = time.time()
                proc = subprocess.run(cmd, cwd=REPO_ROOT)
                if proc.returncode != 0:
                    console.print(f"[red]{cond} rep{rep} failed (exit {proc.returncode}); skipped[/]")
                    continue
                console.print(f"[dim]{cond} rep{rep} took {time.time() - started:.0f}s[/]")
            runs[cond].append({"run_dir": str(run_dir), **summarize_run(run_dir)})

    metrics = [
        "attack_success_rate", "mean_final_score", "refusal_rate", "llm_judge_share",
        "llm_parse_failure_rate", "prompt_fallback_rate", "in_sample_block_rate",
        "heldout_block_rate", "benign_pass_rate",
    ]
    summary = {
        cond: {m: _mean_sd([r[m] for r in rs]) for m in metrics} | {"n_runs": len(rs)}
        for cond, rs in runs.items()
    }

    table = Table(title=f"Pipeline ablation · {tool_file.stem} · {repeats} repeat(s)")
    table.add_column("Metric")
    for cond in chosen:
        table.add_column(f"{cond} (n={summary[cond]['n_runs']})")
    for m in metrics:
        cells = []
        for cond in chosen:
            s = summary[cond][m]
            if s["mean"] is None:
                cells.append("–")
            else:
                cells.append(f"{s['mean']:.2f}" + (f" ± {s['sd']:.2f}" if s["sd"] is not None else ""))
        table.add_row(m, *cells)
    console.print(table)

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ablation_pipeline.json"
    out_path.write_text(json.dumps({"runs": runs, "summary": summary}, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote {out_path}[/]")


if __name__ == "__main__":
    app()
