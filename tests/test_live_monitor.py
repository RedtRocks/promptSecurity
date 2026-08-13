"""Tests for the live attack-cycle terminal view.

Progress reporting is decoration, so the bar for it is: it must never be able to
break or slow a run, and it must actually reflect what the pipeline is doing.
"""

from __future__ import annotations

import threading
from io import StringIO

from rich import box
from rich.console import Console

import agent_hardener.output.live as live_mod
from agent_hardener.output.live import AttackMonitor, _pick_spinner_frames


def _render(monitor: AttackMonitor, width: int = 130) -> str:
    """Render the view to a plain string, as a real terminal would."""
    # file=StringIO keeps the render off the test output; record=True captures it.
    console = Console(width=width, record=True, legacy_windows=False, file=StringIO())
    console.print(monitor.render())
    return console.export_text()


class TestEventHandling:
    def test_states_appear_and_report_phase(self):
        m = AttackMonitor(["data_exfiltration", "destructive_action"])
        m.handle_event({
            "record_index": 1, "phase": "start", "label": "data_exfiltration",
            "strategy": "authority_pretext", "max_iterations": 3,
        })
        m.handle_event({"record_index": 1, "phase": "submitted", "attempt": 2})
        out = _render(m)
        assert "data_exfiltration" in out
        assert "authority_pretext" in out
        assert "waiting on agent" in out
        assert "2/3" in out

    def test_unstarted_cycles_are_shown_as_queued(self):
        """A worker-limited run must not look like the other attacks vanished."""
        m = AttackMonitor(["a", "b", "c"])
        m.handle_event({"record_index": 1, "phase": "start", "label": "a"})
        assert "+2 queued" in _render(m)

    def test_completion_is_counted_once(self):
        m = AttackMonitor(["a", "b"])
        for _ in range(3):  # duplicate 'done' events must not double-count
            m.handle_event({"record_index": 1, "phase": "done", "success": True})
        assert m._completed == 1

    def test_score_and_outcome_are_surfaced(self):
        m = AttackMonitor(["a"])
        m.handle_event({"record_index": 1, "phase": "start", "label": "a"})
        m.handle_event({"record_index": 1, "phase": "graded", "attempt": 1, "score": 0.87})
        m.handle_event({"record_index": 1, "phase": "done", "score": 0.87, "success": True})
        out = _render(m)
        assert "0.87" in out
        assert "SUCCEEDED" in out

    def test_held_attack_reads_as_held(self):
        m = AttackMonitor(["a"])
        m.handle_event({"record_index": 1, "phase": "start", "label": "a"})
        m.handle_event({"record_index": 1, "phase": "done", "score": 0.0, "success": False})
        assert "held" in _render(m)

    def test_injection_provenance_is_visible(self):
        """The operator should see whether a payload actually reached the agent."""
        m = AttackMonitor(["injection_hijack"])
        m.handle_event({
            "record_index": 1, "phase": "start", "label": "injection_hijack",
            "channel": "tool_result",
        })
        assert "inj" in _render(m)
        m.handle_event({"record_index": 1, "phase": "graded", "ingested_untrusted": True})
        assert "inj+landed" in _render(m)

    def test_seed_sweep_is_shown(self):
        m = AttackMonitor(["a"])
        m.handle_event({"record_index": 1, "phase": "start", "label": "a", "max_iterations": 2})
        m.handle_event({"record_index": 1, "phase": "seed", "seed_index": 3, "n_seeds": 5})
        assert "s3/5" in _render(m)

    def test_unknown_index_is_ignored(self):
        m = AttackMonitor(["a"])
        m.handle_event({"phase": "done"})  # no record_index
        assert m._completed == 0


class TestRobustness:
    def test_spinner_frames_survive_the_active_console_encoding(self):
        """A legacy Windows codepage cannot encode braille; writing it would raise
        UnicodeEncodeError and take down the whole run."""
        import sys as _sys

        frames = _pick_spinner_frames()
        assert frames
        frames.encode(getattr(_sys.stdout, "encoding", None) or "ascii")

    def test_render_is_cp1252_safe_when_unicode_is_unavailable(self, monkeypatch):
        """Every glyph in the view must survive a legacy codepage console.

        Glyph safety is chosen explicitly rather than left to renderer
        auto-detection, so this asserts the ASCII path end to end.
        """
        monkeypatch.setattr(live_mod, "_UNICODE_OK", False)
        monkeypatch.setattr(live_mod, "_SPINNER_FRAMES", "|/-\\")
        monkeypatch.setattr(live_mod, "_BOX", box.ASCII)

        m = AttackMonitor(["data_exfiltration", "unstarted_one"])
        m.handle_event({
            "record_index": 1, "phase": "start", "label": "data_exfiltration",
            "channel": "tool_result", "max_iterations": 2,
        })
        m.handle_event({"record_index": 1, "phase": "submitted", "attempt": 1})

        console = Console(width=130, record=True, file=StringIO())
        console.print(m.render())
        console.export_text().encode("cp1252")  # must not raise

    def test_concurrent_events_do_not_corrupt_state(self):
        """handle_event is called from worker threads."""
        m = AttackMonitor([f"a{i}" for i in range(20)])

        def worker(idx: int) -> None:
            m.handle_event({"record_index": idx, "phase": "start", "label": f"a{idx}"})
            for attempt in range(5):
                m.handle_event({
                    "record_index": idx, "phase": "graded",
                    "attempt": attempt, "score": attempt / 10,
                })
            m.handle_event({"record_index": idx, "phase": "done", "success": False})

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 21)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert m._completed == 20
        assert len(m._states) == 20
        _render(m)  # must still render cleanly
