"""Live SAMOS policy gateway — production deployment surface.

This module turns a generated `SAMOSPolicy` JSON document into a runtime control:
a FastAPI service that sits between an LLM client and a real agent endpoint,
applies the three deterministic SAMOS gates (capability / taint / enforcement
rule) to every trajectory the underlying agent returns, and rewrites blocked
tool calls before they reach the caller.

Architecture::

    LLM client ──POST /run──▶ gateway ──POST /run──▶ real agent
                                  │
                                  ├─ load SAMOSPolicy at startup
                                  ├─ wrap AgentClient in PolicyEnforcingAgentClient
                                  ├─ emit per-request enforcement audit
                                  └─ expose /policy and /audit for observability

The gateway is a thin orchestration layer over the existing
`PolicyEnforcingAgentClient`. All policy logic lives in `verifier/`; this file
only handles the HTTP/JSON-RPC surface and operational concerns (audit, health,
graceful shutdown).
"""

import json
import sqlite3
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock
from collections.abc import AsyncIterator
from typing import Any, Callable, Optional

from agent_hardener.shared.agent_client import AgentClient
from agent_hardener.shared.schemas import SAMOSPolicy
from agent_hardener.shared.settings import Settings
from agent_hardener.verifier import PolicyEnforcingAgentClient

# ── Stateful taint persistence ───────────────────────────────────────────────
# Each /run is a separate HTTP request, so without persistence the gateway would
# forget a session's confidentiality taint between requests: an agent could read
# a secret in one request and exfiltrate it in the next (a "sleeper" attack).
# The gateway therefore stores the taint per client-supplied ``session_id``.
# Requests without a session_id stay stateless, exactly as before; defaulting
# them to a shared session would let one client's reads taint every other client.

DB_PATH = "gateway_sessions.db"


def init_db(db_path: "str | Path" = DB_PATH) -> None:
    """Create the session-taint table if it does not exist."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                current_taint TEXT DEFAULT 'low'
            )
            """
        )


def load_session_taint(db_path: "str | Path", session_id: str) -> Optional[str]:
    """Return the persisted taint for ``session_id``, or None for a new session."""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT current_taint FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    return row[0] if row else None


def save_session_taint(db_path: "str | Path", session_id: str, taint: str) -> None:
    """Persist ``taint`` as the current taint of ``session_id``."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, current_taint) VALUES (?, ?) "
            "ON CONFLICT(session_id) DO UPDATE SET current_taint=excluded.current_taint",
            (session_id, taint),
        )


# FastAPI is an optional dependency. Import at module level (not inside the
# factory) so runtime type-hint resolution works for FastAPI's request parser;
# guard it so the rest of the package still imports without FastAPI installed.
try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = HTTPException = Request = JSONResponse = None  # type: ignore
    _FASTAPI_AVAILABLE = False


# ── Policy loading ────────────────────────────────────────────────────────────


def load_policy(policy_path: Path) -> SAMOSPolicy:
    """Load a SAMOSPolicy from either a raw policy JSON or a full report.json.

    Accepts:
      - The raw object emitted by `policy.model_dump_json()`
      - A `report.json` containing `stage3_policy` at the top level
      - A `hardening_history.json` entry's `policy` field (used for round-by-round
        deploys)

    Raises FileNotFoundError or ValueError on bad input — fail fast at startup.
    """
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    data = json.loads(policy_path.read_text(encoding="utf-8"))

    if isinstance(data, dict) and "tool_name" in data and "enforcement_rules" in data:
        candidate = data
    elif isinstance(data, dict) and "stage3_policy" in data:
        candidate = data["stage3_policy"]
    elif isinstance(data, dict) and "policy" in data and isinstance(data["policy"], dict):
        candidate = data["policy"]
    else:
        raise ValueError(
            f"Could not locate a SAMOSPolicy object in {policy_path}. "
            "Expected a raw policy, a report.json, or a hardening round entry."
        )

    return SAMOSPolicy.model_validate(candidate)


# ── App factory ───────────────────────────────────────────────────────────────


# Type alias for the inner agent dependency — keeps the gateway testable without
# spinning up a real HTTP server behind it.
AgentFactory = Callable[[], Any]


def create_app(
    *,
    policy: Optional[SAMOSPolicy] = None,
    policy_path: Optional[Path] = None,
    agent_endpoint: Optional[str] = None,
    agent_auth_token: str = "",
    inner_agent: Any = None,
    audit_log_path: Optional[Path] = None,
    audit_ring_size: int = 500,
    session_db_path: "Optional[str | Path]" = None,
) -> "FastAPI":
    """Build the FastAPI gateway app.

    Exactly one of `policy` or `policy_path` must be provided.
    Exactly one of `agent_endpoint` or `inner_agent` must be provided.
    `session_db_path` is the SQLite file holding per-session taint
    (default: ``gateway_sessions.db`` in the working directory).
    """
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the gateway. Install with: "
            "pip install -e \".[dev]\"  (or add fastapi + uvicorn to your deps)."
        )

    # ── Resolve inputs ────────────────────────────────────────────────────────
    if policy is None and policy_path is None:
        raise ValueError("create_app requires policy or policy_path")
    if policy is None:
        policy = load_policy(policy_path)  # type: ignore[arg-type]

    if inner_agent is None and not agent_endpoint:
        raise ValueError("create_app requires agent_endpoint or inner_agent")
    if inner_agent is None:
        settings = Settings(
            agent_endpoint=agent_endpoint,
            agent_auth_token=agent_auth_token,
        )
        inner_agent = AgentClient(settings)

    enforcer = PolicyEnforcingAgentClient(inner_agent, policy)

    session_db = session_db_path if session_db_path is not None else DB_PATH
    init_db(session_db)

    # ── Audit ring + optional JSONL sink ──────────────────────────────────────
    audit_ring: deque[dict[str, Any]] = deque(maxlen=audit_ring_size)
    audit_lock = Lock()

    def _record_audit(event: dict[str, Any]) -> None:
        with audit_lock:
            audit_ring.append(event)
        if audit_log_path is not None:
            try:
                audit_log_path.parent.mkdir(parents=True, exist_ok=True)
                with audit_log_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            except Exception:
                # Audit-log failures must not break request handling.
                pass

    # ── App ───────────────────────────────────────────────────────────────────
    @asynccontextmanager
    async def _lifespan(_app: "FastAPI") -> AsyncIterator[None]:
        try:
            yield
        finally:
            try:
                inner_agent.close()
            except Exception:
                pass

    app = FastAPI(
        title="agent-hardener policy gateway",
        version="1.0",
        description="Runtime SAMOS policy enforcement in front of an MCP-style agent.",
        lifespan=_lifespan,
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy_tool": policy.tool_name,
            "enforcement_rules": len(policy.enforcement_rules),
            "taint_rules": len(policy.session_taint_rules.taint_propagation_rules),
            "initial_taint": policy.session_taint_rules.initial_session_taint.value,
        }

    @app.get("/policy")
    def get_policy() -> dict[str, Any]:
        """Return the policy the gateway is currently enforcing."""
        result: dict[str, Any] = json.loads(policy.model_dump_json())
        return result

    @app.get("/audit")
    def get_audit(limit: int = 50) -> dict[str, Any]:
        """Return the most recent enforcement events (newest last)."""
        with audit_lock:
            events = list(audit_ring)
        if limit > 0:
            events = events[-limit:]
        return {"count": len(events), "events": events}

    @app.post("/run")
    async def run(request: Request) -> JSONResponse:
        """Forward a prompt to the inner agent and enforce the policy on the result.

        Accepts the same body shape as the protected agent: ``{"prompt": "..."}``,
        plus an optional ``session_id``. With a session_id, the session's taint
        is carried over from earlier requests and saved afterwards.
        Returns the AgentTrajectory JSON, augmented with ``enforcement_log`` so
        clients can see which gates fired without having to call ``/audit``.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be valid JSON.")

        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise HTTPException(status_code=400, detail="Body must contain a non-empty 'prompt' string.")

        session_id = body.get("session_id")
        if session_id is not None and (not isinstance(session_id, str) or not session_id.strip()):
            raise HTTPException(status_code=400, detail="'session_id' must be a non-empty string.")
        persisted_taint = load_session_taint(session_db, session_id) if session_id else None

        t0 = time.time()
        try:
            trajectory = enforcer.run_task(prompt, starting_taint=persisted_taint)
        except Exception as exc:
            _record_audit({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "prompt_preview": prompt[:200],
                "error": f"inner agent raised: {exc}",
                "elapsed_ms": int((time.time() - t0) * 1000),
            })
            raise HTTPException(status_code=502, detail=f"Inner agent error: {exc}")

        log = list(enforcer.last_enforcement_log)
        blocked = any(e.get("action") == "BLOCK" for e in log)

        final_taint = enforcer.last_final_taint
        if session_id:
            save_session_taint(session_db, session_id, final_taint)

        audit_event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "prompt_preview": prompt[:200],
            "tool_call_count": len(trajectory.tool_calls),
            "refusal_detected": trajectory.refusal_detected,
            "blocked": blocked,
            "enforcement_log": log,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "session_id": session_id,
            "final_taint": final_taint,
        }
        _record_audit(audit_event)

        payload = json.loads(trajectory.model_dump_json())
        payload["enforcement_log"] = log
        payload["policy_tool"] = policy.tool_name
        payload["session_id"] = session_id
        payload["final_taint"] = final_taint
        return JSONResponse(payload)

    @app.post("/tools/list")
    async def tools_list() -> dict[str, Any]:
        """MCP-compatible tool listing — delegates to the inner agent.

        Returns the tool annotation from the loaded policy so clients can see
        the SAMOS labels (read/write confidentiality, capability allowed-sets)
        the gateway is enforcing for each registered tool.
        """
        annotation = policy.gateway_enforcement.tool_annotation
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": [json.loads(annotation.model_dump_json())],
            },
        }

    # Stash references on the app for tests / introspection.
    app.state.policy = policy
    app.state.enforcer = enforcer
    app.state.audit_ring = audit_ring
    app.state.session_db = session_db

    return app
