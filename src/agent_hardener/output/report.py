"""Output layer — JSON and HTML report generation.

Produces two output files in the specified directory:
  - report.json: Complete machine-readable pipeline output (all three stages)
  - report.html: Self-contained HTML dashboard with Chart.js visualizations
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, PackageLoader, select_autoescape

if TYPE_CHECKING:
    from agent_hardener.verifier import VerifierVerdict

from agent_hardener.shared.schemas import (
    AttackRecord,
    FailureAnalysisReport,
    MCPToolDefinition,
    SAMOSPolicy,
)


def generate_report(
    tool: MCPToolDefinition,
    attack_records: list[AttackRecord],
    analysis: FailureAnalysisReport,
    policy: SAMOSPolicy,
    output_dir: Path,
    hardening_history: list[dict[str, Any]] | None = None,
    success_threshold: float = 0.95,
    benign_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Generate the JSON report and HTML dashboard.

    success_threshold must match the run's attack_success_threshold so the
    verifier and security/utility metrics count the same attacks as "successful".

    benign_dir optionally points at an alternative benign-suite directory (e.g.
    trajectories recorded from a live agent rather than hand-authored ones).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Deterministic verifier output — auditable per-record verdicts.
    from agent_hardener.verifier import (
        verify_all_records,
        evaluate_security_utility,
        load_benign_suite,
    )
    verifier_verdicts = verify_all_records(attack_records, policy, success_threshold)
    verdicts_by_id = {v.record_id: v for v in verifier_verdicts}

    # Security/utility tradeoff: replay benign tasks through the SAME gates so a
    # deny-everything policy (100% attack coverage) is exposed by a collapsed
    # benign-pass-rate. Missing benign suite -> utility reported as unmeasured.
    benign_suite = load_benign_suite(tool.name, benign_dir)
    security_utility = evaluate_security_utility(
        attack_records, policy, benign_suite, success_threshold
    )

    report_data = {
        "pipeline_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": json.loads(tool.model_dump_json()),
        "stage1_attack_records": [json.loads(r.model_dump_json()) for r in attack_records],
        "stage2_failure_analysis": json.loads(analysis.model_dump_json()),
        "stage3_policy": json.loads(policy.model_dump_json()),
        "policy_verifier_verdicts": [v.to_dict() for v in verifier_verdicts],
        "security_utility": json.loads(security_utility.model_dump_json()),
        # Where the benign trajectories came from. Hand-authored suites make the
        # benign pass rate partly circular (we wrote both the task and its calls),
        # so the provenance must travel with the number, not be assumed.
        "benign_suite_provenance": (
            benign_suite.provenance if benign_suite else "none"
        ),
        "hardening_history": hardening_history or [],
    }

    json_path = output_dir / "report.json"
    json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

    html_path = output_dir / "report.html"
    env = Environment(
        loader=PackageLoader("agent_hardener", "output/templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    chart_data = _build_chart_data(attack_records, policy, verifier_verdicts)
    attack_summaries = _build_attack_summaries(attack_records, policy, verdicts_by_id)
    hardening_showcase = _build_hardening_showcase(hardening_history or [])
    headline = _build_headline_metrics(attack_records, policy, verifier_verdicts)

    html_content = template.render(
        tool=tool,
        attack_records=attack_records,
        attack_summaries=attack_summaries,
        analysis=analysis,
        policy=policy,
        verifier_verdicts=[v.to_dict() for v in verifier_verdicts],
        security_utility=security_utility,
        hardening_showcase=hardening_showcase,
        headline=headline,
        chart_data_json=json.dumps(chart_data),
        report_data_json=json.dumps(report_data),
        generated_at=report_data["generated_at"],
    )
    html_path.write_text(html_content, encoding="utf-8")

    return json_path, html_path


def _bootstrap_proportion_ci(
    outcomes: list[bool],
    n_boot: int = 2000,
    seed: int = 42,
    ci: float = 0.95,
) -> tuple[float, float] | None:
    """Percentile bootstrap CI for a proportion (fraction of True in ``outcomes``).

    Returns None when there is nothing to resample. Used to put honest error bars
    on the headline attack-success rate and policy-coverage numbers so a reviewer
    sees uncertainty, not just a point estimate. Deterministic given ``seed``.
    """
    import random

    n = len(outcomes)
    if n == 0:
        return None
    rng = random.Random(seed)
    rates: list[float] = []
    for _ in range(n_boot):
        s = sum(outcomes[rng.randrange(n)] for _ in range(n))
        rates.append(s / n)
    rates.sort()
    lo_q = (1 - ci) / 2
    hi_q = 1 - lo_q
    lo = rates[int(lo_q * len(rates))]
    hi = rates[min(len(rates) - 1, int(hi_q * len(rates)))]
    return (lo, hi)


def _build_headline_metrics(
    records: list[AttackRecord],
    policy: SAMOSPolicy,
    verdicts: list[VerifierVerdict],
) -> dict[str, Any]:
    """Top-of-page summary tiles."""
    n = len(records)
    n_success = sum(1 for r in records if r.attempt_number_of_success is not None)
    n_refusals = sum(1 for r in records if r.refusal_occurred)
    cov = policy.policy_coverage
    n_succ_attacks = max(1, n_success)
    coverage_pct = cov.attacks_fully_blocked_by_policy / n_succ_attacks if n_success else 0.0

    # Bootstrap CIs (percentile) so headline rates carry error bars, not just a
    # point estimate. Success rate resamples the per-record success indicator;
    # coverage resamples the "blocked?" indicator over the successful-attack subset.
    success_outcomes = [r.attempt_number_of_success is not None for r in records]
    success_rate_ci = _bootstrap_proportion_ci(success_outcomes)
    verdict_by_id = {v.record_id: v for v in verdicts}
    blocked_over_success: list[bool] = []
    for r in records:
        if r.attempt_number_of_success is None:
            continue
        v = verdict_by_id.get(r.record_id)
        blocked_over_success.append(bool(v and v.final_status.value == "BLOCKED"))
    coverage_ci = _bootstrap_proportion_ci(blocked_over_success)

    # Seed sweep variance: only meaningful when at least one record has >1 score.
    seed_stddevs = []
    for r in records:
        if r.seed_scores and len(r.seed_scores) > 1:
            mean = sum(r.seed_scores) / len(r.seed_scores)
            var = sum((s - mean) ** 2 for s in r.seed_scores) / (len(r.seed_scores) - 1)
            seed_stddevs.append(math.sqrt(var))
    mean_seed_stddev = sum(seed_stddevs) / len(seed_stddevs) if seed_stddevs else None

    iters_to_success = [
        r.attempt_number_of_success
        for r in records
        if r.attempt_number_of_success is not None
    ]
    mean_iters = sum(iters_to_success) / len(iters_to_success) if iters_to_success else None

    return {
        "total_attacks": n,
        "successful_attacks": n_success,
        "success_rate": (n_success / n) if n else 0.0,
        "success_rate_ci_low": success_rate_ci[0] if success_rate_ci else None,
        "success_rate_ci_high": success_rate_ci[1] if success_rate_ci else None,
        "policy_coverage_ci_low": coverage_ci[0] if coverage_ci else None,
        "policy_coverage_ci_high": coverage_ci[1] if coverage_ci else None,
        "refusals": n_refusals,
        "refusal_rate": (n_refusals / n) if n else 0.0,
        "fully_blocked_by_policy": cov.attacks_fully_blocked_by_policy,
        "partially_mitigated": cov.attacks_partially_mitigated,
        "model_level": cov.attacks_requiring_model_level_defense,
        "unmitigated": cov.unmitigated_attacks,
        "policy_coverage_pct": coverage_pct,
        "enforcement_rules": len(policy.enforcement_rules),
        "taint_propagation_rules": len(policy.session_taint_rules.taint_propagation_rules),
        "mean_seed_stddev": mean_seed_stddev,
        "mean_iters_to_success": mean_iters,
    }


def _build_chart_data(
    records: list[AttackRecord],
    policy: SAMOSPolicy,
    verdicts: list[VerifierVerdict],
) -> dict[str, Any]:
    """Pre-compute data structures for Chart.js charts."""

    # Per-record summary: ID, harm, score, mean+/-std if seeds present, status.
    per_record = []
    for r in records:
        seed_mean = None
        seed_std = None
        if r.seed_scores and len(r.seed_scores) > 1:
            seed_mean = sum(r.seed_scores) / len(r.seed_scores)
            var = sum((s - seed_mean) ** 2 for s in r.seed_scores) / (len(r.seed_scores) - 1)
            seed_std = math.sqrt(var)
        per_record.append({
            "record_id": r.record_id,
            "harm": r.harm_category.value,
            "score": r.final_score,
            "seed_scores": list(r.seed_scores),
            "seed_mean": seed_mean,
            "seed_std": seed_std,
            "iterations": len(r.attack_trajectory),
            "intensity": r.attack_intensity.value,
            "success": r.attempt_number_of_success is not None,
            "refusal": r.refusal_occurred,
        })

    iteration_data = []
    for r in records:
        iteration_data.append({
            "label": r.harm_category.value,
            "record_id": r.record_id,
            "data": [
                {"attempt": it.attempt_number, "score": it.score}
                for it in r.attack_trajectory
            ],
        })

    cov = policy.policy_coverage
    coverage_data = {
        "fully_blocked": cov.attacks_fully_blocked_by_policy,
        "partially_mitigated": cov.attacks_partially_mitigated,
        "model_level": cov.attacks_requiring_model_level_defense,
        "unmitigated": cov.unmitigated_attacks,
    }

    verdict_counts = {"BLOCKED": 0, "AUDITED": 0, "REQUIRES_CONFIRMATION": 0, "UNMITIGATED": 0}
    for v in verdicts:
        verdict_counts[v.final_status.value] = verdict_counts.get(v.final_status.value, 0) + 1

    enforcement_actions: dict[str, int] = {}
    for rule in policy.enforcement_rules:
        a = rule.action.value
        enforcement_actions[a] = enforcement_actions.get(a, 0) + 1

    return {
        "per_record": per_record,
        "iteration_progressions": iteration_data,
        "policy_coverage": coverage_data,
        "verdict_counts": verdict_counts,
        "enforcement_action_counts": enforcement_actions,
    }


def _build_hardening_showcase(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize hardening rounds for the HTML timeline."""
    showcase: list[dict[str, Any]] = []
    for entry in history:
        attack_rows = [dict(row) for row in entry.get("attack_rows", [])]
        policy_summary = dict(entry.get("policy_summary", {}))
        coverage = dict(policy_summary.get("coverage", entry.get("policy_coverage", {})))

        showcase.append({
            "round": entry.get("round", 0),
            "attack_intensity": entry.get("attack_intensity", ""),
            "attack_intensity_label": _display_attack_intensity(entry.get("attack_intensity", "")),
            "attack_successes": entry.get("attack_successes", 0),
            "attack_total": entry.get("attack_total", 0),
            "success_rate": float(entry.get("success_rate", 0.0)),
            "agent_run_success_rate": float(entry.get("agent_run_success_rate", entry.get("success_rate", 0.0))),
            "primary_exploit_vector": entry.get("primary_exploit_vector", ""),
            "policy_coverage": coverage,
            "enforcement_rules": entry.get("enforcement_rules", 0),
            "learned_attack_signatures": entry.get("learned_attack_signatures", []),
            "attack_rows": attack_rows,
            "policy_summary": {
                "confidentiality": policy_summary.get("confidentiality", {}),
                "session_taint": policy_summary.get("session_taint", ""),
                "coverage": coverage,
                "enforcement_rules": policy_summary.get("enforcement_rules", []),
            },
        })
    return showcase


def _display_attack_intensity(raw: str) -> str:
    if raw == "strong":
        return "Hard"
    return raw.capitalize() if raw else "Round"


def _build_attack_summaries(
    records: list[AttackRecord],
    policy: SAMOSPolicy,
    verdicts_by_id: dict[str, VerifierVerdict],
) -> list[dict[str, object]]:
    """Per-attack rows enriched with verifier verdicts and seed-sweep variance."""
    summaries: list[dict[str, object]] = []
    for record in records:
        matched_rules = [
            rule for rule in policy.enforcement_rules
            if rule.motivated_by_attack == record.record_id
        ]
        touched_tool = bool(record.successful_tool_calls or record.failed_tool_calls)
        if not touched_tool:
            touched_tool = any(it.trajectory.tool_calls for it in record.attack_trajectory)

        attack_success = record.attempt_number_of_success is not None
        verdict = verdicts_by_id.get(record.record_id)
        verdict_status = verdict.final_status.value if verdict else "UNMITIGATED"

        if attack_success and verdict_status == "BLOCKED":
            mitigation_status = "blocked-by-policy"
        elif attack_success and verdict_status in ("AUDITED", "REQUIRES_CONFIRMATION"):
            mitigation_status = "partially-mitigated"
        elif attack_success and matched_rules:
            mitigation_status = "rule-attached"
        elif attack_success:
            mitigation_status = "unmitigated"
        else:
            mitigation_status = "attack-failed"

        first_prompt = (
            record.attack_trajectory[0].prompt_used
            if record.attack_trajectory else record.final_prompt_used
        )

        seed_mean = None
        seed_std = None
        if record.seed_scores and len(record.seed_scores) > 1:
            seed_mean = sum(record.seed_scores) / len(record.seed_scores)
            var = sum((s - seed_mean) ** 2 for s in record.seed_scores) / (len(record.seed_scores) - 1)
            seed_std = math.sqrt(var)

        summaries.append({
            "record_id": record.record_id,
            "harm_category": record.harm_category.value,
            "attack_intensity": record.attack_intensity.value,
            "final_score": record.final_score,
            "attack_success": attack_success,
            "worked_on_tool": touched_tool,
            "failure_type": record.failure_type.value,
            "first_prompt": first_prompt,
            "final_prompt": record.final_prompt_used,
            "iterations": len(record.attack_trajectory),
            "refusal_occurred": record.refusal_occurred,
            "attempt_of_success": record.attempt_number_of_success,
            "seed_scores": list(record.seed_scores),
            "seed_mean": seed_mean,
            "seed_std": seed_std,
            "policy_rule_ids": [rule.rule_id for rule in matched_rules],
            "policy_actions": [rule.action.value for rule in matched_rules],
            "policy_mitigated": mitigation_status,
            "verdict_status": verdict_status,
            "verdict_notes": verdict.notes if verdict else [],
            "verdict_triggered_rules": verdict.triggered_rule_ids if verdict else [],
            "verdict_capability_denials": verdict.triggered_capability_denials if verdict else [],
        })

    return summaries
