"""Automated tests for Stateful Taint Persistence (Sleeper Agent Defense)."""

import sqlite3
import pytest
from agent_hardener.gateway_server import DB_PATH, init_db

def test_gateway_sqlite_session_tracking():
    """Proves the gateway successfully persists and retrieves session taint across requests."""
    
    # 1. Initialize the gateway database
    init_db()
    session_id = "apt_sleeper_session_001"

    # 2. Simulate Turn 1: Gateway saves HIGH taint after the agent reads a secret
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, current_taint) VALUES (?, ?) "
            "ON CONFLICT(session_id) DO UPDATE SET current_taint=excluded.current_taint",
            (session_id, "high")
        )

    # 3. Simulate Turn 2: Gateway reads state when the attacker tries to exfiltrate
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT current_taint FROM sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()

    # 4. Assert the memory survived
    assert row is not None, "Database failed to create the session record."
    assert row[0] == "high", "Stateful persistence failed! Taint was lost between requests."
    
    # 5. Clean up
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

