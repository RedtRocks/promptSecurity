"""Run repeated live MCP evaluations and compute aggregate statistics.

This script keeps the existing hardening pipeline unchanged and adds a
reproducible outer loop for repeated trials and confidence-style summaries.

Usage:
    python scripts/run_repeated_eval.py http://127.0.0.1:8080 --config config.yaml --repeats 3
"""

from __future__ import annotations

import json
import math
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent_hardener.shared.settings import Settings  # noqa: E402
from scripts.fetch_mcp_tools import fetch_tools  # noqa: E402

app = typer.Typer()
console = Console()


def _kill_process_tree(pid: int) -> None:
    """Best-effort process-tree kill for timeout handling."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
        )
        return

    try:
        os.killpg(pid, 9)
    except Exception:
        try:
            os.kill(pid, 9)
        except Exception:
            pass


def _run_cmd_with_timeout(
    cmd: list[str],
    timeout_sec: int,
    heartbeat_sec: int,
    label: str,
) -> tuple[str, int, str, str]:
    """Run a command with periodic heartbeat and hard timeout.

    Returns: (status, exit_code, stdout, stderr)
    status in {"OK", "FAIL", "TIMEOUT"}
    """
    creationflags = 0
    popen_kwargs: dict = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=creationflags,
        **popen_kwargs,
    )

    start = time.time()
    next_heartbeat = start + heartbeat_sec

    while proc.poll() is None:
        now = time.time()
        elapsed = int(now - start)

        if now >= next_heartbeat:
            console.print(f"    [dim]{label}: running ({elapsed}s elapsed)...[/]")
            next_heartbeat += heartbeat_sec

        if elapsed >= timeout_sec:
            _kill_process_tree(proc.pid)
            stdout, stderr = proc.communicate(timeout=10)
            stderr = (stderr or "") + (
                f"\nProcess exceeded timeout of {timeout_sec} seconds and was terminated."
            )
            return "TIMEOUT", 124, stdout or "", stderr

        time.sleep(1)

    stdout, stderr = proc.communicate()
    code = int(proc.returncode or 0)
    if code == 0:
        return "OK", code, stdout or "", stderr or ""
    return "FAIL", code, stdout or "", stderr or ""


def _save_tools(tools: list[dict], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for tool in tools:
        name = tool.get("name", "unknown")
        path = out_dir / f"{name}.yaml"
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(tool, f, sort_keys=False, default_flow_style=False)
        paths.append(path)
    return paths


def _extract_metrics(report_path: Path, success_threshold: float) -> dict[str, float | int] | None:
    if not report_path.exists():
        return None

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = data.get("stage1_attack_records", [])
    if not isinstance(records, list) or not records:
        return {
            "total_attacks": 0,
            "attack_successes": 0,
            "success_rate": 0.0,
            "mean_score": 0.0,
            "max_score": 0.0,
        }

    scores = [float(r.get("final_score", 0.0)) for r in records]
    successes = sum(1 for s in scores if s > success_threshold)
    total = len(scores)

    return {
        "total_attacks": total,
        "attack_successes": successes,
        "success_rate": successes / total if total else 0.0,
        "mean_score": sum(scores) / total if total else 0.0,
        "max_score": max(scores) if scores else 0.0,
    }


def _ci95(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    stdev = statistics.stdev(values)
    return 1.96 * stdev / math.sqrt(len(values))


@app.command()
def main(
    endpoint: str = typer.Argument(..., help="MCP server endpoint, e.g. http://localhost:8080"),
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to project config"),
    output_dir: Path = typer.Option(Path("./hardener_output/repeated_eval"), "--output-dir", "-o"),
    repeats: int = typer.Option(3, "--repeats", min=1, max=50),
    hardening_rounds: int = typer.Option(1, "--hardening-rounds", min=1, max=10),
    max_iterations: int = typer.Option(2, "--max-iterations", min=1, max=10),
    attack_parallelism: int = typer.Option(1, "--attack-parallelism", min=1, max=8),
    max_tools: int = typer.Option(0, "--max-tools", min=0, help="0 means all discovered tools"),
    per_tool_timeout_sec: int = typer.Option(900, "--per-tool-timeout-sec", min=30),
    heartbeat_sec: int = typer.Option(
        20,
        "--heartbeat-sec",
        min=5,
        help="Emit runner heartbeat logs while waiting on each tool subprocess.",
    ),
    provider: str | None = typer.Option(None, "--provider", help="Optional model override"),
) -> None:
    endpoint = endpoint.rstrip("/")

    settings = Settings.from_yaml(config) if config.exists() else Settings()
    success_threshold = settings.attack_success_threshold

    console.print(f"[cyan]Discovering tools from:[/] {endpoint}")
    tools = fetch_tools(endpoint)
    if not tools:
        console.print("[red]No tools discovered. Check /tools/list support and endpoint URL.[/]")
        raise typer.Exit(1)

    if max_tools > 0:
        tools = tools[:max_tools]

    tools_dir = output_dir / "discovered_tools"
    tool_paths = _save_tools(tools, tools_dir)

    plan = Table(title="Repeated Evaluation Plan")
    plan.add_column("Repeats", style="cyan")
    plan.add_column("Success Threshold", style="white")
    plan.add_column("Tools", style="white")
    plan.add_row(str(repeats), f"{success_threshold:.2f}", str(len(tool_paths)))
    console.print(plan)

    py = str(Path(sys.executable))
    run_rows: list[dict] = []

    for rep in range(1, repeats + 1):
        console.print(f"\n[bold]Repeat {rep}/{repeats}[/]")
        rep_dir = output_dir / f"repeat_{rep:02d}"

        for tool_path in tool_paths:
            tool_name = tool_path.stem
            tool_out = rep_dir / tool_name
            cmd = [
                py,
                "-m",
                "agent_hardener.cli",
                "harden",
                "--tool-file",
                str(tool_path),
                "--config",
                str(config),
                "--agent-endpoint",
                endpoint,
                "--hardening-rounds",
                str(hardening_rounds),
                "--max-iterations",
                str(max_iterations),
                "--attack-parallelism",
                str(attack_parallelism),
                "--output-dir",
                str(tool_out),
            ]
            if provider:
                cmd.extend(["--provider", provider])

            status, exit_code, stdout, stderr = _run_cmd_with_timeout(
                cmd,
                timeout_sec=per_tool_timeout_sec,
                heartbeat_sec=heartbeat_sec,
                label=f"r{rep} {tool_name}",
            )

            tool_out.mkdir(parents=True, exist_ok=True)
            log_path = tool_out / "run.log"
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(stdout)
                if stderr:
                    f.write("\n--- STDERR ---\n")
                    f.write(stderr)

            metrics = None
            if status == "OK":
                metrics = _extract_metrics(tool_out / "report.json", success_threshold)

            run_rows.append(
                {
                    "repeat": rep,
                    "tool": tool_name,
                    "status": status,
                    "exit_code": exit_code,
                    "output_dir": str(tool_out),
                    "log": str(log_path),
                    "metrics": metrics,
                }
            )
            console.print(f"  {tool_name}: {status} (code={exit_code})")

    aggregates: dict[str, dict] = {}
    tool_names = sorted({row["tool"] for row in run_rows})

    for tool_name in tool_names:
        rows = [r for r in run_rows if r["tool"] == tool_name and r["status"] == "OK" and r["metrics"]]
        success_rates = [float(r["metrics"]["success_rate"]) for r in rows]
        mean_scores = [float(r["metrics"]["mean_score"]) for r in rows]
        max_scores = [float(r["metrics"]["max_score"]) for r in rows]

        aggregates[tool_name] = {
            "num_runs": len(rows),
            "success_rate_mean": statistics.mean(success_rates) if success_rates else 0.0,
            "success_rate_stdev": statistics.stdev(success_rates) if len(success_rates) > 1 else 0.0,
            "success_rate_ci95": _ci95(success_rates),
            "mean_score_mean": statistics.mean(mean_scores) if mean_scores else 0.0,
            "mean_score_stdev": statistics.stdev(mean_scores) if len(mean_scores) > 1 else 0.0,
            "mean_score_ci95": _ci95(mean_scores),
            "max_score_mean": statistics.mean(max_scores) if max_scores else 0.0,
            "max_score_stdev": statistics.stdev(max_scores) if len(max_scores) > 1 else 0.0,
            "max_score_ci95": _ci95(max_scores),
        }

    summary = {
        "endpoint": endpoint,
        "repeats": repeats,
        "success_threshold": success_threshold,
        "runs": run_rows,
        "aggregates": aggregates,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "repeated_eval_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    table = Table(title="Repeated Evaluation Aggregates")
    table.add_column("Tool", style="cyan")
    table.add_column("Runs", style="white")
    table.add_column("Success Rate Mean", style="white")
    table.add_column("Success Rate CI95", style="white")
    table.add_column("Mean Score", style="white")

    for tool_name, agg in aggregates.items():
        table.add_row(
            tool_name,
            str(agg["num_runs"]),
            f"{agg['success_rate_mean']:.3f}",
            f"±{agg['success_rate_ci95']:.3f}",
            f"{agg['mean_score_mean']:.3f}",
        )

    console.print()
    console.print(table)
    console.print(f"\n[bold green]Summary:[/] {summary_path}")


if __name__ == "__main__":
    app()
