"""Output layer — JSON and HTML report generation.

Produces two output files in the specified directory:
  - report.json: Complete machine-readable pipeline output (all three stages)
  - report.html: Self-contained HTML dashboard with Chart.js visualizations
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

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
) -> tuple[Path, Path]:
    """Generate the JSON report and HTML dashboard.

    Args:
        tool: The original MCPToolDefinition.
        attack_records: All Stage 1 AttackRecord objects.
        analysis: Stage 2 FailureAnalysisReport.
        policy: Stage 3 SAMOSPolicy.
        output_dir: Directory in which to write output files.

    Returns:
        Tuple of (json_path, html_path).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Assemble the complete report dict ─────────────────────────────────────
    report_data = {
        "pipeline_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": json.loads(tool.model_dump_json()),
        "stage1_attack_records": [
            json.loads(r.model_dump_json()) for r in attack_records
        ],
        "stage2_failure_analysis": json.loads(analysis.model_dump_json()),
        "stage3_policy": json.loads(policy.model_dump_json()),
    }

    # ── Write JSON output ─────────────────────────────────────────────────────
    json_path = output_dir / "report.json"
    json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

    # ── Render HTML dashboard ─────────────────────────────────────────────────
    html_path = output_dir / "report.html"

    env = Environment(
        loader=PackageLoader("agent_hardener", "output/templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    # Pre-compute chart data for injection into the template
    chart_data = _build_chart_data(attack_records, policy)

    html_content = template.render(
        tool=tool,
        attack_records=attack_records,
        analysis=analysis,
        policy=policy,
        chart_data_json=json.dumps(chart_data),
        report_data_json=json.dumps(report_data),
        generated_at=report_data["generated_at"],
    )
    html_path.write_text(html_content, encoding="utf-8")

    return json_path, html_path


def _build_chart_data(
    records: list[AttackRecord],
    policy: SAMOSPolicy,
) -> dict:
    """Pre-compute data structures for Chart.js charts."""

    # Chart 1: Attack score per harm category (bar chart)
    category_scores = {
        r.harm_category.value: r.final_score for r in records
    }

    # Chart 2: Score progression per iteration for each attack (line chart)
    iteration_data: list[dict] = []
    for record in records:
        points = [
            {"attempt": it.attempt_number, "score": it.score}
            for it in record.attack_trajectory
        ]
        iteration_data.append({
            "label": f"{record.harm_category.value} ({record.record_id})",
            "data": points,
        })

    # Chart 3: Policy coverage donut chart
    cov = policy.policy_coverage
    coverage_data = {
        "fully_blocked": cov.attacks_fully_blocked_by_policy,
        "partially_mitigated": cov.attacks_partially_mitigated,
        "model_level": cov.attacks_requiring_model_level_defense,
        "unmitigated": cov.unmitigated_attacks,
    }

    # Chart 4: Exploit type distribution (pie chart)
    exploit_counts: dict[str, int] = {}
    for finding in policy.enforcement_rules:
        # Count by action type as a proxy for severity
        action = finding.action.value
        exploit_counts[action] = exploit_counts.get(action, 0) + 1

    return {
        "category_scores": category_scores,
        "iteration_progressions": iteration_data,
        "policy_coverage": coverage_data,
        "enforcement_action_counts": exploit_counts,
    }
