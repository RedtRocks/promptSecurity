"""Load benign-task suites for the security/utility evaluation.

A benign suite lives at ``benign_tasks/<tool_name>.yaml`` (searched relative to
the current working directory and the repo root). The format mirrors the tool
definitions in ``mcp_tools/``::

    tool_name: read_file
    tasks:
      - task_id: read-workspace-config
        description: Read a legitimate config file inside the workspace.
        tool_calls:
          - tool_name: read_file
            parameters: {path: /workspace/config.yaml}
            success: true

Missing suites are not an error: utility is simply reported as unmeasured so a
run without benign tasks still completes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from agent_hardener.shared.schemas import BenignTask, BenignTaskSuite, ToolCall


def _search_paths(tool_name: str, extra_dir: Optional[Path]) -> list[Path]:
    candidates: list[Path] = []
    if extra_dir is not None:
        candidates.append(extra_dir / f"{tool_name}.yaml")
        candidates.append(extra_dir / f"{tool_name}.yml")
    cwd = Path.cwd()
    candidates.append(cwd / "benign_tasks" / f"{tool_name}.yaml")
    candidates.append(cwd / "benign_tasks" / f"{tool_name}.yml")
    # Repo root relative to this file: src/agent_hardener/verifier/ -> up 3.
    repo_root = Path(__file__).resolve().parents[3]
    candidates.append(repo_root / "benign_tasks" / f"{tool_name}.yaml")
    candidates.append(repo_root / "benign_tasks" / f"{tool_name}.yml")
    return candidates


def load_benign_suite(
    tool_name: str,
    benign_dir: Optional[Path] = None,
) -> Optional[BenignTaskSuite]:
    """Load the benign-task suite for a tool, or None if none exists.

    Args:
        tool_name: Tool whose benign suite to load.
        benign_dir: Optional explicit directory to search first.

    Returns:
        A BenignTaskSuite, or None when no suite file is found.
    """
    for path in _search_paths(tool_name, benign_dir):
        if path.exists():
            return _parse_suite(path, tool_name)
    return None


def _parse_suite(path: Path, tool_name: str) -> BenignTaskSuite:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tasks: list[BenignTask] = []
    for raw in data.get("tasks", []):
        calls = [
            ToolCall(
                tool_name=c.get("tool_name", c.get("name", "unknown")),
                parameters=c.get("parameters", c.get("arguments", {})),
                response=c.get("response"),
                success=c.get("success", True),
                failure_reason=c.get("failure_reason", ""),
            )
            for c in raw.get("tool_calls", [])
        ]
        tasks.append(
            BenignTask(
                task_id=raw.get("task_id", f"benign-{len(tasks) + 1}"),
                description=raw.get("description", ""),
                tool_calls=calls,
            )
        )
    return BenignTaskSuite(tool_name=data.get("tool_name", tool_name), tasks=tasks)
