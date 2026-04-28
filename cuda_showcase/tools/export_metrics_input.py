"""Export compact CSV input for the native CUDA showcase benchmark.

This script reads report.json files produced by agent-hardener and extracts
per-attack records into a compact numeric schema suitable for the C/C++
benchmark binaries.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable

CATEGORY_ORDER = [
    "disinformation",
    "harassment",
    "fraud",
    "cybercrime",
    "copyright",
    "hate_speech",
    "drugs",
    "sexual_content",
]
CATEGORY_INDEX = {name: index for index, name in enumerate(CATEGORY_ORDER)}


def _iter_report_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    if path.is_dir():
        yield from sorted(path.rglob("report.json"))
        return
    raise FileNotFoundError(f"Path not found: {path}")


def export_reports(input_path: Path, output_csv: Path, success_threshold: float) -> int:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    total_rows = 0

    with output_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "report_file",
            "record_id",
            "harm_category_index",
            "final_score",
            "attack_intensity_index",
            "iterations",
            "success_flag",
        ])

        for report_file in _iter_report_files(input_path):
            with report_file.open("r", encoding="utf-8") as fh:
                report = json.load(fh)

            for record in report.get("stage1_attack_records", []):
                category_name = str(record.get("harm_category", "")).strip()
                if category_name not in CATEGORY_INDEX:
                    continue

                final_score = float(record.get("final_score", 0.0))
                attack_intensity = str(record.get("attack_intensity", "easy")).strip().lower()
                intensity_index = {"easy": 0, "medium": 1, "strong": 2}.get(attack_intensity, 0)
                iterations = len(record.get("attack_trajectory", []))
                success_flag = 1 if final_score >= success_threshold else 0

                writer.writerow([
                    str(report_file),
                    record.get("record_id", ""),
                    CATEGORY_INDEX[category_name],
                    f"{final_score:.6f}",
                    intensity_index,
                    iterations,
                    success_flag,
                ])
                total_rows += 1

    return total_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Export agent-hardener report.json files to compact CSV input")
    parser.add_argument("input", type=Path, help="A report.json file or a directory containing report.json files")
    parser.add_argument("--output", type=Path, default=Path("cuda_showcase/data/benchmark_input.csv"), help="Output CSV path")
    parser.add_argument("--success-threshold", type=float, default=0.95, help="Score threshold used to mark success")
    args = parser.parse_args()

    rows = export_reports(args.input, args.output, args.success_threshold)
    print(f"Wrote {rows} benchmark rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
