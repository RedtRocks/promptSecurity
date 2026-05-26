"""Compute Cohen's kappa between two raters from a CSV.

Usage:
    python scripts/cohen_kappa.py path/to/labels.csv \
        --col-a llm_grader --col-b human_grader \
        [--bootstrap 1000] [--seed 42]

CSV must have a header row. Each row is one item with at least two columns
holding the raters' labels (any hashable values — e.g., "success"/"fail",
"A"/"B"/"C"/"D"/"E", or numeric scores you've already discretized).

Output: kappa, percent agreement, observed and expected agreement, and an
optional bootstrap 95% CI on kappa.

This is intentionally dependency-free (stdlib only) so it runs anywhere the
rest of the project does. For Krippendorff's alpha or multi-rater extensions
swap in `nltk.metrics.agreement` or `irrCAC`.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import Counter
from pathlib import Path


def cohen_kappa(labels_a: list, labels_b: list) -> tuple[float, dict]:
    """Compute Cohen's kappa.

    Returns (kappa, diagnostics_dict). Raises ValueError on mismatched lengths.
    """
    if len(labels_a) != len(labels_b):
        raise ValueError(
            f"Mismatched rater lengths: {len(labels_a)} vs {len(labels_b)}"
        )
    n = len(labels_a)
    if n == 0:
        raise ValueError("No items to score.")

    # Observed agreement
    agree = sum(1 for a, b in zip(labels_a, labels_b) if a == b)
    p_o = agree / n

    # Expected agreement (independent raters):
    #   sum over categories c of (P(a=c) * P(b=c))
    count_a = Counter(labels_a)
    count_b = Counter(labels_b)
    categories = set(count_a) | set(count_b)
    p_e = sum((count_a[c] / n) * (count_b[c] / n) for c in categories)

    if p_e == 1.0:
        # Both raters used a single category for every item; kappa undefined.
        kappa = 1.0 if p_o == 1.0 else float("nan")
    else:
        kappa = (p_o - p_e) / (1.0 - p_e)

    return kappa, {
        "n_items": n,
        "agreements": agree,
        "percent_agreement": p_o,
        "expected_agreement": p_e,
        "categories": sorted(map(str, categories)),
        "category_counts_a": {str(k): v for k, v in count_a.items()},
        "category_counts_b": {str(k): v for k, v in count_b.items()},
    }


def bootstrap_kappa_ci(
    labels_a: list,
    labels_b: list,
    n_boot: int = 1000,
    seed: int | None = 42,
    ci: float = 0.95,
) -> tuple[float, float, float]:
    """Bootstrap a CI on Cohen's kappa by resampling item indices with replacement."""
    if n_boot <= 0:
        raise ValueError("n_boot must be positive")
    n = len(labels_a)
    rng = random.Random(seed)
    kappas: list[float] = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        boot_a = [labels_a[i] for i in idx]
        boot_b = [labels_b[i] for i in idx]
        try:
            k, _ = cohen_kappa(boot_a, boot_b)
        except ValueError:
            continue
        if k != k:  # NaN guard
            continue
        kappas.append(k)
    if not kappas:
        return (float("nan"), float("nan"), float("nan"))
    kappas.sort()
    lo_q = (1 - ci) / 2
    hi_q = 1 - lo_q
    lo = kappas[int(lo_q * len(kappas))]
    hi = kappas[min(len(kappas) - 1, int(hi_q * len(kappas)))]
    return sum(kappas) / len(kappas), lo, hi


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv_path", type=Path, help="CSV with rater columns")
    p.add_argument("--col-a", required=True, help="Column name for rater A")
    p.add_argument("--col-b", required=True, help="Column name for rater B")
    p.add_argument("--bootstrap", type=int, default=0, help="Bootstrap iterations for CI (0 = skip)")
    p.add_argument("--ci", type=float, default=0.95, help="Confidence level for bootstrap")
    p.add_argument("--seed", type=int, default=42, help="RNG seed for bootstrap")
    args = p.parse_args()

    if not args.csv_path.exists():
        print(f"ERROR: file not found: {args.csv_path}", file=sys.stderr)
        return 1

    with args.csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if args.col_a not in reader.fieldnames or args.col_b not in reader.fieldnames:
            print(
                f"ERROR: columns {args.col_a!r} and {args.col_b!r} required; "
                f"have {reader.fieldnames}",
                file=sys.stderr,
            )
            return 1
        rows = list(reader)

    labels_a = [r[args.col_a] for r in rows]
    labels_b = [r[args.col_b] for r in rows]

    kappa, diag = cohen_kappa(labels_a, labels_b)

    print(f"n_items:              {diag['n_items']}")
    print(f"raters:               {args.col_a} vs {args.col_b}")
    print(f"categories observed:  {diag['categories']}")
    print(f"agreements:           {diag['agreements']} ({100*diag['percent_agreement']:.1f}%)")
    print(f"expected agreement:   {100*diag['expected_agreement']:.1f}%")
    print(f"Cohen's kappa:        {kappa:.4f}")
    print(f"  interpretation:     {_interpret(kappa)}")

    if args.bootstrap > 0:
        mean, lo, hi = bootstrap_kappa_ci(labels_a, labels_b, args.bootstrap, args.seed, args.ci)
        pct = int(args.ci * 100)
        print(f"  bootstrap mean:    {mean:.4f}")
        print(f"  bootstrap {pct}% CI: [{lo:.4f}, {hi:.4f}] (n={args.bootstrap})")
    return 0


def _interpret(kappa: float) -> str:
    """Landis & Koch (1977) interpretation bands."""
    if kappa != kappa:  # NaN
        return "undefined"
    if kappa < 0:
        return "worse than chance"
    if kappa < 0.20:
        return "slight"
    if kappa < 0.40:
        return "fair"
    if kappa < 0.60:
        return "moderate"
    if kappa < 0.80:
        return "substantial"
    return "almost perfect"


if __name__ == "__main__":
    raise SystemExit(main())
