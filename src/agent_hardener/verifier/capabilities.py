"""Heuristic capability inference for tool calls.

The verifier needs to know which SAMOS capability a tool call exercises
(network / filesystem / environment / execution) so it can check the call
against the policy's CapabilityAnnotations. We infer this from the tool's
name. This is a defensible heuristic, but the mapping should be overridable
per-tool by the caller (e.g., when integrating with the MCP registry).
"""

from __future__ import annotations

from typing import Any

# Substring → SAMOS capability. Order is significant: the first capability
# whose substrings match wins. Adjacent substrings (e.g. "send" + "email")
# disambiguate noisy names.
_CAPABILITY_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("execution", ("execute", "command", "shell", "run_", "spawn", "subprocess", "exec_")),
    ("network", ("http", "fetch", "url", "request", "send_email", "send_message", "post_", "upload", "download", "smtp")),
    ("filesystem", ("file", "read_", "write_", "list_dir", "directory", "path", "open_")),
    ("environment", ("env", "getenv", "setenv", "environ")),
]


def infer_capability(tool_name: str) -> str | None:
    """Return the SAMOS capability label inferred from a tool name, or None.

    Returns one of: "network", "filesystem", "environment", "execution".
    """
    name = tool_name.lower()
    for capability, hints in _CAPABILITY_HINTS:
        for hint in hints:
            if hint in name:
                return capability
    return None


def capability_is_denied(capabilities: Any, capability: str) -> bool:
    """True when the policy denies this capability outright (value is False).

    A CapabilityAnnotations field is either False (denied) or a list of allowed
    values (allowed-set). For deterministic coverage we treat allowed-set as
    "not outright denied" — a finer-grained allowed-set check would require
    parameter-level inspection per tool, which is out of scope for the v1
    verifier.
    """
    value = getattr(capabilities, capability, None)
    return value is False


def capability_allowed_set(capabilities: Any, capability: str) -> list[str] | None:
    """Return the allowed values for a capability, or None if unrestricted/denied."""
    value = getattr(capabilities, capability, None)
    if isinstance(value, list):
        return list(value)
    return None
