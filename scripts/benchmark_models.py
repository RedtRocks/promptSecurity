"""Benchmark generation latency/throughput across models.

Fills the "Measured Results" gap flagged in IMPLEMENTATION_SUMMARY.md and the
roadmap "Benchmark script" item. It drives the project's own LLMProvider (so
routing, Ollama handling, and per-family tuning are exactly what the pipeline
uses) over a fixed prompt battery and reports, per model:

  - runs, failures
  - latency: mean, p50, p95, min, max (seconds)
  - approx throughput: characters/second (a proxy for tokens/sec that needs no
    tokenizer; enough for relative comparison across models)

Usage:
    python scripts/benchmark_models.py \
        --config config.yaml \
        --models ollama/gemma3:27b openai/gpt-4o anthropic/claude-3-5-sonnet-20241022 \
        --runs 5 --out benchmark_results.csv

If --models is omitted, the config's default_model is benchmarked alone.
Results are printed as a table and (optionally) written to CSV for the paper.
This is a measurement tool, not a correctness test — it makes real API calls and
therefore costs money/time; keep --runs small for hosted models.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path

# Make the package importable when run as a plain script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_hardener.shared.llm_provider import LLMProvider  # noqa: E402
from agent_hardener.shared.settings import Settings  # noqa: E402

# A small, fixed battery that mirrors the kinds of calls the pipeline makes:
# short structured request, medium reasoning, longer generation.
_PROMPT_BATTERY = [
    "List three security risks of exposing a filesystem tool to an LLM agent. Be concise.",
    "Explain, in one paragraph, what information-flow control means for AI agent tools.",
    "Draft a short JSON object with keys 'risk', 'severity', 'mitigation' for a command-execution tool.",
]


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    idx = min(len(s) - 1, int(q * len(s)))
    return s[idx]


def benchmark_model(model: str, base: Settings, runs: int, max_tokens: int) -> dict[str, object]:
    """Benchmark a single model by overriding default_model on the base settings."""
    settings = base.model_copy(update={"default_model": model, "grader_model": model})
    try:
        provider = LLMProvider(settings)
    except Exception as exc:  # provider init can fail (bad key, unreachable Ollama)
        return {"model": model, "error": f"init failed: {exc}"}

    latencies: list[float] = []
    char_rates: list[float] = []
    failures = 0
    for i in range(runs):
        prompt = _PROMPT_BATTERY[i % len(_PROMPT_BATTERY)]
        messages = [{"role": "user", "content": prompt}]
        t0 = time.perf_counter()
        try:
            out = provider.chat(messages, temperature=0.3, max_tokens=max_tokens)
        except Exception as exc:
            failures += 1
            print(f"  [{model}] run {i + 1} failed: {exc}", file=sys.stderr)
            continue
        dt = time.perf_counter() - t0
        latencies.append(dt)
        if dt > 0 and out:
            char_rates.append(len(out) / dt)

    if not latencies:
        return {"model": model, "error": "all runs failed", "failures": failures}

    return {
        "model": model,
        "runs": len(latencies),
        "failures": failures,
        "latency_mean_s": round(statistics.fmean(latencies), 3),
        "latency_p50_s": round(_percentile(latencies, 0.50), 3),
        "latency_p95_s": round(_percentile(latencies, 0.95), 3),
        "latency_min_s": round(min(latencies), 3),
        "latency_max_s": round(max(latencies), 3),
        "chars_per_s_mean": round(statistics.fmean(char_rates), 1) if char_rates else 0.0,
    }


def _print_table(results: list[dict[str, object]]) -> None:
    print("\n=== Benchmark results ===")
    for r in results:
        if r.get("error"):
            print(f"- {r['model']}: ERROR — {r['error']}")
            continue
        print(
            f"- {r['model']}: "
            f"mean={r['latency_mean_s']}s  p50={r['latency_p50_s']}s  p95={r['latency_p95_s']}s  "
            f"({r['chars_per_s_mean']} char/s, {r['runs']} runs, {r['failures']} fail)"
        )


def _write_csv(results: list[dict[str, object]], out: Path) -> None:
    cols = [
        "model", "runs", "failures", "latency_mean_s", "latency_p50_s",
        "latency_p95_s", "latency_min_s", "latency_max_s", "chars_per_s_mean", "error",
    ]
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for r in results:
            writer.writerow({c: r.get(c, "") for c in cols})
    print(f"\nWrote {out}")


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--config", type=Path, default=None, help="config.yaml (defaults to env/.env)")
    p.add_argument("--models", nargs="*", default=None, help="Model strings to benchmark")
    p.add_argument("--runs", type=int, default=5, help="Calls per model")
    p.add_argument("--max-tokens", type=int, default=512, help="Max tokens per completion")
    p.add_argument("--out", type=Path, default=None, help="Optional CSV output path")
    args = p.parse_args()

    if args.config and args.config.exists():
        base = Settings.from_yaml(args.config)
    else:
        if args.config:
            print(f"WARNING: {args.config} not found; using env/.env defaults", file=sys.stderr)
        base = Settings()

    models = args.models or [base.default_model]
    print(f"Benchmarking {len(models)} model(s), {args.runs} runs each...")

    results = []
    for m in models:
        print(f"\n> {m}")
        results.append(benchmark_model(m, base, args.runs, args.max_tokens))

    _print_table(results)
    if args.out:
        _write_csv(results, args.out)
    # Non-zero exit if every model errored, so CI/automation can detect failure.
    return 0 if any(not r.get("error") for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
