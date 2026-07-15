"""Run agent-hardener against live MCP tools discovered from a server.

This script is defensive-evaluation oriented: it discovers tool schemas from a live
MCP endpoint and runs the hardening pipeline per tool to measure security posture.

Usage:
    uv run python scripts/run_live_mcp_eval.py http://localhost:8080 --config config.yaml
"""

from __future__ import annotations

import json
import os
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
            console.print(f"  [dim]{label}: running ({elapsed}s elapsed)...[/]")
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


@app.command()
def main(
    endpoint: str = typer.Argument(..., help="MCP server endpoint, e.g. http://localhost:8080"),
    config: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Path to project config"),
    output_dir: Path = typer.Option(Path("./hardener_output/live_mcp_eval"), "--output-dir", "-o"),
    hardening_rounds: int = typer.Option(1, "--hardening-rounds", min=1, max=10),
    max_iterations: int = typer.Option(
        2,
        "--max-iterations",
        min=1,
        max=10,
        help="Maximum refinement iterations per attack for each hardening run.",
    ),
    attack_parallelism: int = typer.Option(
        1,
        "--attack-parallelism",
        min=1,
        max=8,
        help="Maximum number of attack cycles to run concurrently.",
    ),
    max_tools: int = typer.Option(0, "--max-tools", min=0, help="0 means all discovered tools"),
    per_tool_timeout_sec: int = typer.Option(
        900,
        "--per-tool-timeout-sec",
        min=30,
        help="Maximum wall-clock time per tool evaluation before it is marked TIMEOUT.",
    ),
    heartbeat_sec: int = typer.Option(
        20,
        "--heartbeat-sec",
        min=5,
        help="Emit runner heartbeat logs while waiting on each tool subprocess.",
    ),
    provider: str | None = typer.Option(None, "--provider", help="Optional model override"),
) -> None:
    endpoint = endpoint.rstrip("/")
    console.print(f"[cyan]Discovering tools from:[/] {endpoint}")

    tools = fetch_tools(endpoint)
    if not tools:
        console.print("[red]No tools discovered. Check /tools/list support and endpoint URL.[/]")
        raise typer.Exit(1)

    if max_tools > 0:
        tools = tools[:max_tools]

    tools_dir = output_dir / "discovered_tools"
    tool_paths = _save_tools(tools, tools_dir)

    table = Table(title="Live MCP Evaluation Plan")
    table.add_column("Tool", style="cyan")
    table.add_column("Definition", style="white")
    for path in tool_paths:
        table.add_row(path.stem, str(path))
    console.print(table)

    run_summaries: list[dict] = []
    py = str(Path(sys.executable))

    for tool_path in tool_paths:
        tool_name = tool_path.stem
        tool_out = output_dir / tool_name
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

        console.print(f"\n[bold]Running:[/] {tool_name}")
        status, exit_code, stdout, stderr = _run_cmd_with_timeout(
            cmd,
            timeout_sec=per_tool_timeout_sec,
            heartbeat_sec=heartbeat_sec,
            label=tool_name,
        )

        log_path = tool_out / "run.log"
        tool_out.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(stdout)
            if stderr:
                f.write("\n--- STDERR ---\n")
                f.write(stderr)

        run_summaries.append(
            {
                "tool": tool_name,
                "status": status,
                "exit_code": exit_code,
                "output_dir": str(tool_out),
                "log": str(log_path),
            }
        )

        if status == "OK":
            status_rich = "[green]OK[/]"
        elif status == "TIMEOUT":
            status_rich = "[yellow]TIMEOUT[/]"
        else:
            status_rich = "[red]FAIL[/]"
        console.print(f"  Status: {status_rich}  code={exit_code}  log={log_path}")

    summary_path = output_dir / "live_eval_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(run_summaries, f, indent=2)

    result_table = Table(title="Live MCP Evaluation Results")
    result_table.add_column("Tool", style="cyan")
    result_table.add_column("Status", style="white")
    result_table.add_column("Exit Code", style="white")
    result_table.add_column("Output Dir", style="white")
    for item in run_summaries:
        result_table.add_row(item["tool"], item["status"], str(item["exit_code"]), item["output_dir"])
    console.print(result_table)
    console.print(f"\n[bold green]Summary:[/] {summary_path}")


if __name__ == "__main__":
    app()
