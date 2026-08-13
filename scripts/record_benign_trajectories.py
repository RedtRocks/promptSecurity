"""Record benign trajectories from a live agent instead of hand-authoring them.

The security/utility tradeoff (`verifier/utility.py`) replays benign tasks through
the same policy gates as attacks, so the benign pass rate is the false-positive
rate against legitimate use. But in the hand-authored suites we wrote *both* the
task and the exact tool calls it produces — the same circularity objection that
applies to self-grading. A reviewer can reasonably ask whether the policy passes
those tasks because it preserves utility or because we picked calls it would pass.

This script removes that. For each task it sends the task's `prompt` (falling back
to `description`) to the live agent and records whatever the agent *actually* does,
writing a suite marked `provenance: recorded`.

Two rules keep the output honest:

  1. **Empty trajectories are dropped, not kept.** A task where the agent made no
     tool calls (it refused, or misread the request) replays as "nothing to block",
     which the utility metric would score as a pass — silently inflating BPR with
     tasks that never exercised the tool. Dropped tasks are counted and reported.
  2. **No injections are ever sent.** These are the legitimate-use fixtures; a
     payload here would poison the utility baseline.

Usage:
    python scripts/record_benign_trajectories.py --tool read_file --config config.yaml
    python scripts/record_benign_trajectories.py --all --config config.yaml --out-dir benign_tasks_recorded

Then point a run at the recorded suites:
    agent-hardener analyze --tool-file mcp_tools/read_file.yaml \
        --config config.yaml --benign-dir benign_tasks_recorded
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_hardener.shared.agent_client import AgentClient  # noqa: E402
from agent_hardener.shared.schemas import MCPToolDefinition  # noqa: E402
from agent_hardener.shared.settings import Settings  # noqa: E402
from agent_hardener.verifier.benign_loader import load_benign_suite  # noqa: E402


def _load_tool(tool_name: str, corpus_dir: Path) -> MCPToolDefinition | None:
    for ext in ("yaml", "yml"):
        path = corpus_dir / f"{tool_name}.{ext}"
        if path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if "tool" in data and isinstance(data["tool"], dict):
                data = data["tool"]
            return MCPToolDefinition.from_mcp_json(data)
    return None


def record_suite(
    tool_name: str,
    settings: Settings,
    corpus_dir: Path,
    benign_dir: Path | None,
) -> dict[str, Any] | None:
    """Re-record one tool's benign suite against the live agent."""
    suite = load_benign_suite(tool_name, benign_dir)
    if suite is None or not suite.tasks:
        print(f"  [skip] {tool_name}: no benign suite to re-record")
        return None

    tool = _load_tool(tool_name, corpus_dir)
    if tool is None:
        print(f"  [skip] {tool_name}: no tool definition in {corpus_dir}")
        return None

    agent = AgentClient(settings)
    # Give the agent the same tool context a real run would, so its behaviour
    # matches the conditions under which the policy will be evaluated.
    agent.set_tool_context(tool)

    recorded: list[dict[str, Any]] = []
    dropped: list[dict[str, str]] = []
    try:
        for task in suite.tasks:
            request = task.prompt or task.description
            if not request.strip():
                dropped.append({"task_id": task.task_id, "reason": "no prompt or description"})
                continue

            trajectory = agent.run_task(request)  # never pass injections here

            if not trajectory.tool_calls:
                # Would replay as "nothing to block" and inflate the benign pass
                # rate with a task that never touched the tool.
                reason = (
                    "agent refused" if trajectory.refusal_detected
                    else "agent made no tool calls"
                )
                dropped.append({"task_id": task.task_id, "reason": reason})
                print(f"  [drop] {task.task_id}: {reason}")
                continue

            recorded.append({
                "task_id": task.task_id,
                "description": task.description,
                "prompt": request,
                "tool_calls": [
                    {
                        "tool_name": c.tool_name,
                        "parameters": c.parameters,
                        "success": c.success,
                        "response": c.response,
                    }
                    for c in trajectory.tool_calls
                ],
            })
            names = ", ".join(c.tool_name for c in trajectory.tool_calls)
            print(f"  [ok]   {task.task_id}: {names}")
    finally:
        agent.close()

    return {
        "tool_name": tool_name,
        "provenance": "recorded",
        "tasks": recorded,
        "recording_notes": {
            "n_source_tasks": len(suite.tasks),
            "n_recorded": len(recorded),
            "n_dropped": len(dropped),
            "dropped": dropped,
            "agent_endpoint": settings.agent_endpoint,
            "agent_model_env": "see AGENT_LLM_MODEL on the agent server",
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tool", action="append", default=[], help="Tool name (repeatable)")
    ap.add_argument("--all", action="store_true", help="Re-record every suite found")
    ap.add_argument("--config", type=Path, default=Path("config.yaml"))
    ap.add_argument("--corpus-dir", type=Path, default=REPO_ROOT / "mcp_tools")
    ap.add_argument("--benign-dir", type=Path, default=REPO_ROOT / "benign_tasks")
    ap.add_argument("--out-dir", type=Path, default=REPO_ROOT / "benign_tasks_recorded")
    ap.add_argument("--agent-endpoint", default="", help="Override agent endpoint")
    args = ap.parse_args()

    settings = Settings.from_yaml(args.config) if args.config.is_file() else Settings()
    if args.agent_endpoint:
        settings = settings.model_copy(update={"agent_endpoint": args.agent_endpoint})

    tool_names: list[str] = list(args.tool)
    if args.all:
        tool_names = sorted(
            p.stem for p in args.benign_dir.glob("*.y*ml")
        )
    if not tool_names:
        ap.error("give --tool NAME (repeatable) or --all")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Recording against agent at {settings.agent_endpoint}\n")

    total_recorded = total_dropped = 0
    for name in tool_names:
        print(f"{name}:")
        suite = record_suite(name, settings, args.corpus_dir, args.benign_dir)
        if suite is None:
            continue
        out_path = args.out_dir / f"{name}.yaml"
        out_path.write_text(
            "# Benign trajectories RECORDED from a live agent (not hand-authored).\n"
            "# Regenerate with scripts/record_benign_trajectories.py\n"
            + yaml.safe_dump(suite, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        notes = suite["recording_notes"]
        total_recorded += notes["n_recorded"]
        total_dropped += notes["n_dropped"]
        print(f"  -> {out_path} ({notes['n_recorded']} recorded, {notes['n_dropped']} dropped)\n")

    print(f"Done: {total_recorded} trajectories recorded, {total_dropped} dropped.")
    if total_dropped:
        print(
            "Dropped tasks made no tool calls; keeping them would have counted as "
            "'not blocked' and inflated the benign pass rate."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
