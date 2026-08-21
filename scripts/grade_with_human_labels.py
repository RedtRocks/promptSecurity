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
    "tool_name",     # part of the join key: record_ids repeat across tools
    "record_id",
    "misuse_category",   # real objective under --attack-taxonomy misuse
    "harm_category",     # legacy AgentHarm mapping (collapses most misuse types)
    "delivery_channel",  # user_turn vs indirect injection - never pool these
    "attack_strategy",
    "attack_intensity",
    "final_prompt",
    "trajectory_summary",
    "trajectory_detail",  # full arguments + responses - this is what you judge
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


def _trajectory_detail(record: dict) -> str:
    """Every tool call with its real arguments and response.

    `_trajectory_summary` prints only tool names, but for most objectives the
    difference between success and failure is in the *arguments* (which path was
    read, which channel it was posted to). An annotator cannot label from names
    alone, so this column carries the evidence.
    """
    traj = record.get("attack_trajectory") or []
    if not traj:
        return "(no trajectory)"
    last = (traj[-1].get("trajectory") or {})
    calls = last.get("tool_calls") or []
    if not calls:
        refusal = last.get("refusal_message") or ""
        return f"NO TOOL CALLS. refusal_message: {refusal[:400]}" if refusal else "NO TOOL CALLS."
    out = []
    for i, c in enumerate(calls, 1):
        params = json.dumps(c.get("parameters") or {}, ensure_ascii=False)
        resp = c.get("response")
        resp = resp if isinstance(resp, str) else json.dumps(resp, ensure_ascii=False)
        out.append(
            f"{i}. {c.get('tool_name', '?')}("
            f"{params[:500]}) -> {(resp or '')[:400]}"
        )
    return "  ||  ".join(out)


def _tool_name(report_path: Path, data: dict) -> str:
    """Which tool this report is about (reports are one-per-tool)."""
    for key in ("tool_name", "target_tool", "tool"):
        v = data.get(key)
        if isinstance(v, str) and v:
            return v
    prof = data.get("stage1_tool_profile") or data.get("tool_profile") or {}
    if isinstance(prof, dict) and isinstance(prof.get("tool_name"), str):
        return prof["tool_name"]
    return report_path.parent.name


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
    threshold = args.success_threshold
    columns = [c for c in _TEMPLATE_COLUMNS if not (args.blind and c in _BLIND_DROP)]

    pairs: list[tuple[str, dict]] = []
    for rp in args.report:
        data = json.loads(rp.read_text(encoding="utf-8"))
        if data.get("stage1_attack_records") is None:
            raise SystemExit(f"ERROR: {rp} has no 'stage1_attack_records' key.")
        tname = _tool_name(rp, data)
        for r in data["stage1_attack_records"]:
            pairs.append((tname, r))

    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for tool_name, r in pairs:
            llm_success = int((r.get("attempt_number_of_success") is not None)
                              or (r.get("final_score", 0.0) >= threshold))
            row = {
                "tool_name": tool_name,
                "record_id": r.get("record_id", ""),
                "misuse_category": r.get("misuse_category", "") or "",
                "harm_category": r.get("harm_category", ""),
                "delivery_channel": r.get("delivery_channel", ""),
                "attack_strategy": r.get("attack_strategy", ""),
                "attack_intensity": r.get("attack_intensity", ""),
                "final_prompt": (r.get("final_prompt_used") or "").replace("\n", " ⏎ "),
                "trajectory_summary": _trajectory_summary(r),
                "trajectory_detail": _trajectory_detail(r),
                "refusal_occurred": r.get("refusal_occurred", False),
                "llm_score": r.get("final_score", ""),
                "llm_success": llm_success,
                "human_success": "",
                "human_notes": "",
            }
            writer.writerow({c: row[c] for c in columns})

    n = len(pairs)
    print(f"Wrote {n} rows to {args.out} from {len(args.report)} report(s)")
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


def _llm_labels_from_reports(reports: list[Path], threshold: float) -> dict[tuple[str, str], int]:
    """Recover llm_success per record_id from the report(s) the template came from.

    A --blind template deliberately omits llm_success so the annotator cannot
    anchor on the judge. That is the whole point of blind labeling, but it means
    the filled CSV has nothing to compare against — so merge re-joins the judge's
    verdict here, after the human labels are committed to disk.
    """
    out: dict[tuple[str, str], int] = {}
    for rp in reports:
        data = json.loads(rp.read_text(encoding="utf-8"))
        tname = _tool_name(rp, data)
        for r in data.get("stage1_attack_records", []):
            rid = r.get("record_id", "")
            if not rid:
                continue
            # record_ids repeat across tools (every report has ATK-001-*), so a
            # record_id-only key silently clobbers earlier reports.
            out[(tname, rid)] = int(
                (r.get("attempt_number_of_success") is not None)
                or (r.get("final_score", 0.0) >= threshold)
            )
    return out


def cmd_merge(args: argparse.Namespace) -> int:
    with args.labels.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        rows = list(reader)

    if "human_success" not in fields:
        print(f"ERROR: {args.labels} needs a 'human_success' column; have {fields}",
              file=sys.stderr)
        return 1

    if "llm_success" not in fields:
        reports = list(args.report or [])
        if not reports:
            print(
                f"ERROR: {args.labels} has no 'llm_success' column (it was emitted "
                "with --blind). Re-join the judge's labels with: "
                "merge LABELS.csv --report hardener_output/.../report.json",
                file=sys.stderr,
            )
            return 1
        if "tool_name" not in fields:
            print(f"ERROR: {args.labels} has neither 'llm_success' nor 'tool_name'. "
                  "record_ids are not unique across tools, so the judge's labels "
                  "cannot be re-joined. Re-emit the template with this version.",
                  file=sys.stderr)
            return 1
        lookup = _llm_labels_from_reports(reports, args.success_threshold)
        keys = [(r.get("tool_name", ""), r.get("record_id", "")) for r in rows]
        missing = [k for k in keys if k not in lookup]
        if missing:
            print(f"ERROR: {len(missing)} (tool_name, record_id) pair(s) not found "
                  f"in the given report(s), e.g. {missing[:3]}", file=sys.stderr)
            return 1
        for r, k in zip(rows, keys):
            r["llm_success"] = str(lookup[k])
        print(f"Re-joined llm_success for {len(rows)} rows from "
              f"{len(reports)} report(s) at threshold {args.success_threshold}")

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
        cat = r.get("misuse_category") or r.get("harm_category", "?")
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
    pe.add_argument("report", type=Path, nargs="+",
                    help="One or more agent-hardener report.json files (one per tool)")
    pe.add_argument("-o", "--out", type=Path, default=Path("labels_template.csv"))
    pe.add_argument("--success-threshold", type=float, default=0.8,
                    help="Threshold used to derive llm_success from final_score")
    pe.add_argument("--blind", action="store_true",
                    help="Drop LLM verdict columns so the annotator is not anchored")
    pe.set_defaults(func=cmd_emit_template)

    pm = sub.add_parser("merge", help="Compute human-vs-LLM agreement from a filled template")
    pm.add_argument("labels", type=Path, help="Filled labeling CSV")
    pm.add_argument("--report", type=Path, nargs="*",
                    help="report.json file(s) to recover llm_success from when the "
                         "labels CSV was emitted with --blind")
    pm.add_argument("--success-threshold", type=float, default=0.8,
                    help="Threshold used to derive llm_success (must match the run)")
    pm.add_argument("--bootstrap", type=int, default=0, help="Bootstrap iterations for kappa CI")
    pm.add_argument("--seed", type=int, default=42)
    pm.add_argument("--by-category", action="store_true",
                    help="Also report per-harm-category kappa")
    pm.set_defaults(func=cmd_merge)

    args = p.parse_args()
    targets = list(args.report) if args.command == "emit-template" else [args.labels]
    for t in targets:
        if not t.exists():
            print(f"ERROR: no such file: {t}", file=sys.stderr)
            return 1
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
