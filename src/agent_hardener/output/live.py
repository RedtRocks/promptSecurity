"""Live terminal view for long-running attack cycles.

An attack cycle is slow: every iteration makes an agent call plus two or three
LLM calls, and cycles run concurrently. A single aggregate spinner therefore sits
motionless for minutes, which makes a working pipeline look hung. This module
turns the `on_progress` events emitted by `stage1.refiner.run_attack_cycle` into
a table that updates as the work happens — per attack: which iteration it is on,
what it is doing right now, its latest score, and whether the agent refused.

Thread-safety: `handle_event` is called from worker threads, so all state changes
take the lock. Rendering is driven by Rich's own refresh timer via
`Live(get_renderable=...)` rather than by the workers, so no worker ever touches
the console.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import Any

from rich import box
from rich.console import Group, RenderableType
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

# What each phase should read as in the "Doing" column. Present tense: the row
# shows what the cycle is busy with at this instant.
_PHASE_LABELS: dict[str, str] = {
    "start": "queued",
    "prompting": "building structured prompt",
    "submitted": "waiting on agent",
    "grading": "grading trajectory",
    "graded": "graded",
    "refining": "reflecting / refining prompt",
    "seed": "starting repeat",
    "done": "done",
}

def _console_supports_unicode() -> bool:
    """Whether stdout's encoding can carry the non-ASCII glyphs we emit.

    Windows consoles frequently run a legacy codepage (cp1252), which cannot
    encode box-drawing or braille characters — writing them raises
    UnicodeEncodeError and takes the whole run down. Progress decoration must
    never be able to do that, so we choose glyphs we know will survive rather
    than relying on the renderer to downgrade them for us.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "─⠋".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


_UNICODE_OK = _console_supports_unicode()


def _pick_spinner_frames() -> str:
    """Braille spinner where the console can encode it, ASCII otherwise."""
    return "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if _UNICODE_OK else "|/-\\"


_SPINNER_FRAMES = _pick_spinner_frames()
# Explicit box style: never leave glyph safety to renderer auto-detection.
_BOX = box.SQUARE if _UNICODE_OK else box.ASCII


class _AttackState:
    __slots__ = (
        "index", "label", "strategy", "channel", "phase", "attempt",
        "max_iterations", "score", "refused", "n_tool_calls", "finished",
        "success", "seed_index", "n_seeds", "started_at", "updated_at",
        "ingested_untrusted",
    )

    def __init__(self, index: int, label: str) -> None:
        self.index = index
        self.label = label
        self.strategy = ""
        self.channel = "user_turn"
        self.phase = "start"
        self.attempt = 0
        self.max_iterations = 0
        self.score: float | None = None
        self.refused = False
        self.n_tool_calls = 0
        self.finished = False
        self.success = False
        self.seed_index = 0
        self.n_seeds = 0
        self.started_at = time.monotonic()
        self.updated_at = time.monotonic()
        self.ingested_untrusted = False


class AttackMonitor:
    """Thread-safe live view of in-flight attack cycles."""

    def __init__(self, labels: list[str], *, title: str = "Attack cycles") -> None:
        self._lock = threading.Lock()
        self._title = title
        self._states: dict[int, _AttackState] = {}
        self._labels = labels
        self._completed = 0
        self._total = len(labels)
        self._started = time.monotonic()
        # Progress object is only read during render (single-threaded), so its
        # own lack of thread-safety is not an issue here.
        self._progress = Progress(
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        )
        self._task = self._progress.add_task("Attack cycles", total=self._total)

    # ── worker-side ───────────────────────────────────────────────────────────

    def handle_event(self, event: dict[str, Any]) -> None:
        """Consume one progress event. Safe to call from any thread."""
        idx = event.get("record_index")
        if idx is None:
            return
        phase = str(event.get("phase", ""))
        with self._lock:
            state = self._states.get(idx)
            if state is None:
                label = event.get("label") or self._label_for(idx)
                state = _AttackState(idx, str(label))
                self._states[idx] = state

            state.phase = phase
            state.updated_at = time.monotonic()

            if "label" in event:
                state.label = str(event["label"])
            if "strategy" in event:
                state.strategy = str(event["strategy"] or "")
            if "channel" in event:
                state.channel = str(event["channel"])
            if "max_iterations" in event:
                state.max_iterations = int(event["max_iterations"])
            if "attempt" in event:
                state.attempt = int(event["attempt"])
            if "score" in event and event["score"] is not None:
                state.score = float(event["score"])
            if event.get("refused"):
                state.refused = True
            if "n_tool_calls" in event:
                state.n_tool_calls = int(event["n_tool_calls"])
            if event.get("ingested_untrusted"):
                state.ingested_untrusted = True
            if phase == "seed":
                state.seed_index = int(event.get("seed_index", 0))
                state.n_seeds = int(event.get("n_seeds", 0))

            if phase == "done" and not state.finished:
                state.finished = True
                state.success = bool(event.get("success", False))
                self._completed += 1

    def _label_for(self, idx: int) -> str:
        # record_index is 1-based in the CLI.
        pos = idx - 1
        return self._labels[pos] if 0 <= pos < len(self._labels) else f"attack {idx}"

    # ── render-side ───────────────────────────────────────────────────────────

    def render(self) -> RenderableType:
        """Build the current view. Called by Rich's refresh thread."""
        frame = _SPINNER_FRAMES[int(time.monotonic() * 10) % len(_SPINNER_FRAMES)]

        table = Table(
            show_header=True, header_style="bold cyan", border_style="dim",
            expand=True, title=None, box=_BOX,
        )
        table.add_column("#", style="dim", width=3, justify="right")
        table.add_column("Objective", width=26)
        table.add_column("Technique", width=22, style="dim")
        table.add_column("Iter", width=6, justify="center")
        table.add_column("Doing", width=30)
        table.add_column("Score", width=7, justify="right")
        table.add_column("Notes", width=20)

        with self._lock:
            self._progress.update(self._task, completed=self._completed)
            states = [self._states[k] for k in sorted(self._states)]
            for st in states:
                table.add_row(*self._row(st, frame))
            pending = self._total - len(states)

        if pending > 0:
            table.add_row(
                "", f"[dim]+{pending} queued[/]", "", "", "[dim]waiting for a worker[/]", "", "",
            )

        return Group(table, self._progress)

    def _row(self, st: _AttackState, frame: str) -> tuple[str, ...]:
        if st.finished:
            doing = (
                "[red]SUCCEEDED (exploit)[/]" if st.success
                else "[green]held (no exploit)[/]"
            )
        else:
            waited = time.monotonic() - st.updated_at
            label = _PHASE_LABELS.get(st.phase, st.phase)
            doing = f"{frame} {label}"
            # Surface a slow step rather than looking frozen — a single agent or
            # LLM call can legitimately take a while.
            if waited > 5:
                doing += f" [dim]({waited:.0f}s)[/]"

        iters = (
            f"{st.attempt}/{st.max_iterations}" if st.max_iterations else str(st.attempt)
        )
        if st.n_seeds:
            iters += f" s{st.seed_index}/{st.n_seeds}"

        if st.score is None:
            score = "[dim]-[/]"
        else:
            colour = "red" if st.score >= 0.8 else "yellow" if st.score > 0 else "green"
            score = f"[{colour}]{st.score:.2f}[/]"

        notes = []
        if st.refused:
            notes.append("[green]refused[/]")
        if st.channel == "tool_result":
            # "inj" = payload sent; "+landed" = it actually reached the agent's
            # context, which is the precondition for the integrity gate to matter.
            notes.append(
                "[magenta]inj+landed[/]" if st.ingested_untrusted else "[magenta]inj[/]"
            )

        return (
            str(st.index),
            st.label,
            st.strategy or "[dim]-[/]",
            iters,
            doing,
            score,
            " ".join(notes),
        )
