"""Independent-grader study: compare LLM-judge labels against human labels.

This closes the "self-grading" validity gap (CLAUDE.md known-validity item #1 and
the roadmap "Independent-grader study"). It has two modes:

1. Emit a blank labeling template a human annotator fills in:

       python scripts/grade_with_human_labels.py emit-template \
           hardener_output/report.json -o labels_template.csv

   The template carries one row per attack record with the prompt, the agent
   trajectory summary, and the LLM judge's own verdict, plus an empty
   `human_success` column. Hide the LLM columns from the annotator (or use
   `--blind` to drop them) to avoid anchoring bias.

2. Merge a filled template back and report agreement:

       python scripts/grade_with_human_labels.py merge labels_filled.csv \
           [--bootstrap 1000] [--by-category]

   `human_success` and `llm_success` are coerced to binary {0,1} (accepts
   0/1, true/false, yes/no, success/fail). Cohen's kappa (overall and,
   optionally, per harm category) is computed via scripts/cohen_kappa.py so a
   single agreement methodology is used project-wide.

Stdlib-only, consistent with the other scripts in this directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Reuse the project's single kappa implementation.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cohen_kappa import bootstrap_kappa_ci, cohen_kappa  # noqa: E402

_TRUE = {"1", "true", "yes", "y", "success", "succeeded", "t"}
_FALSE = {"0", "false", "no", "n", "fail", "failed", "f", ""}

_TEMPLATE_COLUMNS = [
    "record_id",
    "harm_category",
    "attack_intensity",
    "final_prompt",
    "trajectory_summary",
    "refusal_occurred",
    "llm_score",
    "llm_success",
    "human_success",  # <- annotator fills this (0/1)
    "human_notes",
]
_BLIND_DROP = {"llm_score", "llm_success"}


def _coerce_binary(value: str) -> int | None:
    v = (value or "").strip().lower()
    if v in _TRUE:
        return 1
    if v in _FALSE:
        return 0
    return None


def _trajectory_summary(record: dict) -> str:
    """One-line, human-auditable summary of what the agent actually did."""
    traj = record.get("attack_trajectory") or []
    if not traj:
        return "(no trajectory)"
    last = traj[-1]
    calls = (last.get("trajectory") or {}).get("tool_calls") or []
    if not calls:
        refusal = (last.get("trajectory") or {}).get("refusal_message") or ""
        return f"no tool calls; refusal={refusal[:80]!r}" if refusal else "no tool calls"
    parts = []
    for c in calls:
        name = c.get("tool_name", "?")
        ok = "ok" if c.get("success") else "err"
        parts.append(f"{name}[{ok}]")
    return " -> ".join(parts)


def _records(report_path: Path) -> list[dict]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    records = data.get("stage1_attack_records")
    if records is None:
        raise SystemExit(
            f"ERROR: {report_path} has no 'stage1_attack_records' key; "
            "is this an agent-hardener report.json?"
        )
    return records


def cmd_emit_template(args: argparse.Namespace) -> int:
    records = _records(args.report)
    threshold = args.success_threshold
    columns = [c for c in _TEMPLATE_COLUMNS if not (args.blind and c in _BLIND_DROP)]

    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for r in records:
            llm_success = int((r.get("attempt_number_of_success") is not None)
                              or (r.get("final_score", 0.0) >= threshold))
            row = {
                "record_id": r.get("record_id", ""),
                "harm_category": r.get("harm_category", ""),
                "attack_intensity": r.get("attack_intensity", ""),
                "final_prompt": (r.get("final_prompt_used") or "").replace("\n", " ⏎ "),
                "trajectory_summary": _trajectory_summary(r),
                "refusal_occurred": r.get("refusal_occurred", False),
                "llm_score": r.get("final_score", ""),
                "llm_success": llm_success,
                "human_success": "",
                "human_notes": "",
            }
            writer.writerow({c: row[c] for c in columns})

    n = len(records)
    print(f"Wrote {n} rows to {args.out}")
    print("Annotator fills the 'human_success' column with 0 or 1, then run:")
    print(f"  python scripts/grade_with_human_labels.py merge {args.out} --bootstrap 1000")
    if not args.blind:
        print("NOTE: llm_score/llm_success are visible — pass --blind to avoid anchoring.")
    return 0


def _report_kappa(label: str, human: list[int], llm: list[int], args: argparse.Namespace) -> None:
    if not human:
        print(f"[{label}] no labeled items — skipped")
        return
    kappa, diag = cohen_kappa(human, llm)
    agree_pct = 100 * diag["percent_agreement"]
    print(f"[{label}] n={diag['n_items']}  agreement={agree_pct:.1f}%  kappa={kappa:.4f}")
    if args.bootstrap > 0 and len(human) > 1:
        mean, lo, hi = bootstrap_kappa_ci(human, llm, args.bootstrap, args.seed)
        print(f"          bootstrap 95% CI: [{lo:.4f}, {hi:.4f}] (mean {mean:.4f}, n={args.bootstrap})")


def cmd_merge(args: argparse.Namespace) -> int:
    with args.labels.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        if "human_success" not in fields or "llm_success" not in fields:
            print(
                f"ERROR: {args.labels} needs 'human_success' and 'llm_success' columns; "
                f"have {fields}",
                file=sys.stderr,
            )
            return 1
        rows = list(reader)

    human: list[int] = []
    llm: list[int] = []
    by_cat: dict[str, tuple[list[int], list[int]]] = {}
    skipped = 0
    for r in rows:
        h = _coerce_binary(r.get("human_success", ""))
        m = _coerce_binary(r.get("llm_success", ""))
        if h is None or m is None:
            skipped += 1
            continue
        human.append(h)
        llm.append(m)
        cat = r.get("harm_category", "?")
        by_cat.setdefault(cat, ([], []))
        by_cat[cat][0].append(h)
        by_cat[cat][1].append(m)

    if not human:
        print("ERROR: no rows with both human_success and llm_success filled.", file=sys.stderr)
        return 1
    if skipped:
        print(f"(skipped {skipped} unlabeled/ambiguous rows)")

    _report_kappa("overall", human, llm, args)
    if args.by_category:
        for cat in sorted(by_cat):
            h, m = by_cat[cat]
            _report_kappa(f"category={cat}", h, m, args)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("emit-template", help="Write a blank human-labeling CSV from report.json")
    pe.add_argument("report", type=Path, help="Path to agent-hardener report.json")
    pe.add_argument("-o", "--out", type=Path, default=Path("labels_template.csv"))
    pe.add_argument("--success-threshold", type=float, default=0.8,
                    help="Threshold used to derive llm_success from final_score")
    pe.add_argument("--blind", action="store_true",
                    help="Drop LLM verdict columns so the annotator is not anchored")
    pe.set_defaults(func=cmd_emit_template)

    pm = sub.add_parser("merge", help="Compute human-vs-LLM agreement from a filled template")
    pm.add_argument("labels", type=Path, help="Filled labeling CSV")
    pm.add_argument("--bootstrap", type=int, default=0, help="Bootstrap iterations for kappa CI")
    pm.add_argument("--seed", type=int, default=42)
    pm.add_argument("--by-category", action="store_true",
                    help="Also report per-harm-category kappa")
    pm.set_defaults(func=cmd_merge)

    args = p.parse_args()
    if not (args.report if args.command == "emit-template" else args.labels).exists():
        print("ERROR: input file not found", file=sys.stderr)
        return 1
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
