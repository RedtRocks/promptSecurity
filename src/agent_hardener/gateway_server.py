"""Live SAMOS policy gateway — production deployment surface.

This module turns a generated `SAMOSPolicy` JSON document into a runtime control:
a FastAPI service that sits between an LLM client and a real agent endpoint,
applies the three deterministic SAMOS gates (capability / taint / enforcement
rule) to every trajectory the underlying agent returns, and rewrites blocked
tool calls before they reach the caller.
"""

import json
import time
import sqlite3
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

# --- STATEFUL TAINT PERSISTENCE: Database Setup ---
DB_PATH = "gateway_sessions.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                current_taint TEXT DEFAULT 'low'
            )
        """)
init_db()
# --------------------------------------------------


try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = HTTPException = Request = JSONResponse = None  # type: ignore
    _FASTAPI_AVAILABLE = False


# ── Policy loading ────────────────────────────────────────────────────────────

def load_policy(policy_path: Path) -> SAMOSPolicy:
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
) -> "FastAPI":
    
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the gateway. Install with: "
            "pip install -e \".[dev]\"  (or add fastapi + uvicorn to your deps)."
        )

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
                pass

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
        result: dict[str, Any] = json.loads(policy.model_dump_json())
        return result

    @app.get("/audit")
    def get_audit(limit: int = 50) -> dict[str, Any]:
        with audit_lock:
            events = list(audit_ring)
        if limit > 0:
            events = events[-limit:]
        return {"count": len(events), "events": events}

    @app.post("/run")
    async def run(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be valid JSON.")

        prompt = body.get("prompt")
        # Extract session_id for taint tracking
        session_id = body.get("session_id", "default_session")

        if not isinstance(prompt, str) or not prompt.strip():
            raise HTTPException(status_code=400, detail="Body must contain a non-empty 'prompt' string.")

        # --- STATEFUL TAINT PERSISTENCE: Read Previous State ---
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT current_taint FROM sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            persisted_taint = row[0] if row else None
        # -------------------------------------------------------

        t0 = time.time()
        try:
            # Pass the retrieved taint state to the enforcer
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

        # --- STATEFUL TAINT PERSISTENCE: Save New State ---
        final_taint = persisted_taint or policy.session_taint_rules.initial_session_taint.value
        if log and "final_taint" in log[-1]:
            final_taint = log[-1]["final_taint"]
            
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO sessions (session_id, current_taint) 
                VALUES (?, ?) 
                ON CONFLICT(session_id) DO UPDATE SET current_taint=excluded.current_taint
            """, (session_id, str(final_taint)))
        # --------------------------------------------------

        audit_event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "prompt_preview": prompt[:200],
            "tool_call_count": len(trajectory.tool_calls),
            "refusal_detected": trajectory.refusal_detected,
            "blocked": blocked,
            "enforcement_log": log,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "session_id": session_id,
            "final_taint": str(final_taint)
        }
        _record_audit(audit_event)

        payload = json.loads(trajectory.model_dump_json())
        payload["enforcement_log"] = log
        payload["policy_tool"] = policy.tool_name
        return JSONResponse(payload)

    @app.post("/tools/list")
    async def tools_list() -> dict[str, Any]:
        annotation = policy.gateway_enforcement.tool_annotation
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": [json.loads(annotation.model_dump_json())],
            },
        }

    app.state.policy = policy
    app.state.enforcer = enforcer
    app.state.audit_ring = audit_ring

    return app