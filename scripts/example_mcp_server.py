"""Example MCP server with real tools for testing agent-hardener.

This server implements the MCP protocol with several tools that demonstrate
different vulnerability patterns:
- send_email: Network + filesystem capability over-permissiveness
- read_file: Insufficient path validation
- execute_command: Dangerous capability with weak authorization

Run with:
    uv run uvicorn scripts.example_mcp_server:app --port 8080

Then test with:
    uv run python scripts/fetch_mcp_tools.py http://localhost:8080
    uv run agent-hardener analyze --tool-file mcp_tools/send_email.yaml --config config.yaml
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel

app = FastAPI(title="Example MCP Server")


# ── Tool implementations ──────────────────────────────────────────────────────

tools_registry = {
    "send_email": {
        "name": "send_email",
        "description": "Send an email message to one or more recipients via SMTP",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Email recipient addresses",
                },
                "subject": {
                    "type": "string",
                    "description": "Email subject line",
                },
                "body": {
                    "type": "string",
                    "description": "Email body text (plain text)",
                },
                "attachment_path": {
                    "type": "string",
                    "description": "Optional filesystem path to attach a file",
                },
            },
            "required": ["to", "subject", "body"],
        },
    },
    "read_file": {
        "name": "read_file",
        "description": "Read the contents of a file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file",
                },
                "encoding": {
                    "type": "string",
                    "description": "Character encoding (default: utf-8)",
                },
            },
            "required": ["path"],
        },
    },
    "execute_command": {
        "name": "execute_command",
        "description": "Execute a shell command and return stdout/stderr",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Working directory (defaults to current directory)",
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in seconds (default: 30)",
                },
            },
            "required": ["command"],
        },
    },
    "list_directory": {
        "name": "list_directory",
        "description": "List files and directories in the given path",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Include subdirectories recursively",
                },
            },
            "required": ["path"],
        },
    },
}


def execute_tool(tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Simulate tool execution (intentionally vulnerable for testing)."""
    
    if tool_name == "send_email":
        to = parameters.get("to", [])
        subject = parameters.get("subject", "")
        attachment = parameters.get("attachment_path")
        
        # Vulnerability: No recipient validation (allows sending to arbitrary addresses)
        # Vulnerability: No path validation on attachment (allows reading any file)
        result = f"Email sent to {', '.join(to)} with subject '{subject}'"
        if attachment:
            result += f"\nAttachment: {attachment}"
        
        return {"success": True, "output": result}
    
    elif tool_name == "read_file":
        path = parameters.get("path", "")
        
        # Vulnerability: No path traversal protection
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read(1000)  # Limit for demo
            return {"success": True, "output": content}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
    
    elif tool_name == "execute_command":
        command = parameters.get("command", "")
        timeout = parameters.get("timeout", 30)
        
        # Vulnerability: No command whitelist or sandboxing
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout[:500],
                "error": result.stderr[:500] if result.stderr else "",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
    
    elif tool_name == "list_directory":
        path = parameters.get("path", ".")
        recursive = parameters.get("recursive", False)
        
        # Vulnerability: No directory access control
        try:
            p = Path(path)
            if recursive:
                files = [str(f.relative_to(p)) for f in p.rglob("*") if f.is_file()]
            else:
                files = [f.name for f in p.iterdir()]
            
            return {"success": True, "output": files[:100]}  # Limit for demo
        except Exception as exc:
            return {"success": False, "error": str(exc)}
    
    return {"success": False, "error": f"Unknown tool: {tool_name}"}


# ── MCP endpoints ─────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    prompt: str


@app.post("/tools/list")
async def tools_list(request: Request) -> dict[str, Any]:
    """MCP tools/list endpoint."""
    body = await request.json()
    
    # Return MCP JSON-RPC format
    return {
        "jsonrpc": "2.0",
        "id": body.get("id", 1),
        "result": {
            "tools": list(tools_registry.values()),
        },
    }


@app.post("/tools/call")
async def tools_call(request: Request) -> dict[str, Any]:
    """MCP tools/call endpoint."""
    body = await request.json()
    params = body.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    
    result = execute_tool(tool_name, arguments)
    
    return {
        "jsonrpc": "2.0",
        "id": body.get("id", 1),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result),
                }
            ],
        },
    }


@app.post("/run")
async def run_agent(req: RunRequest) -> dict[str, Any]:
    """Agent endpoint that processes prompts and calls tools.
    
    This is a VERY simple agent that heuristically decides which tool to call
    based on keywords in the prompt. A real agent would use an LLM to plan.
    """
    prompt = req.prompt.lower()
    tool_calls = []
    
    # Simple heuristic routing
    if "email" in prompt or "send" in prompt:
        # Extract email addresses (basic pattern)
        import re
        emails = re.findall(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', prompt)
        if not emails:
            emails = ["default@example.com"]
        
        tool_calls.append({
            "tool_name": "send_email",
            "parameters": {
                "to": emails[:3],
                "subject": "Auto-generated from prompt",
                "body": prompt[:200],
            },
            "success": True,
            "response": f"Email sent to {', '.join(emails)}",
        })
    
    if "read" in prompt and "file" in prompt:
        # Look for file paths
        import re
        paths = re.findall(r'/[\w/\.]+|[A-Z]:\\[\w\\\.]+', prompt)
        path = paths[0] if paths else "/etc/passwd"
        
        result = execute_tool("read_file", {"path": path})
        tool_calls.append({
            "tool_name": "read_file",
            "parameters": {"path": path},
            "success": result.get("success", False),
            "response": result.get("output", result.get("error")),
        })
    
    if "execute" in prompt or "command" in prompt or "run" in prompt:
        # Extract command (very naive)
        words = prompt.split()
        cmd_idx = -1
        for i, w in enumerate(words):
            if w in ["execute", "command", "run"]:
                cmd_idx = i
                break
        
        command = " ".join(words[cmd_idx+1:cmd_idx+5]) if cmd_idx > -1 else "echo 'test'"
        result = execute_tool("execute_command", {"command": command})
        tool_calls.append({
            "tool_name": "execute_command",
            "parameters": {"command": command},
            "success": result.get("success", False),
            "response": result.get("output", result.get("error")),
        })
    
    if "list" in prompt and ("dir" in prompt or "folder" in prompt):
        import re
        paths = re.findall(r'/[\w/]+|[A-Z]:\\[\w\\]+', prompt)
        path = paths[0] if paths else "."
        
        result = execute_tool("list_directory", {"path": path, "recursive": False})
        tool_calls.append({
            "tool_name": "list_directory",
            "parameters": {"path": path},
            "success": result.get("success", False),
            "response": result.get("output", result.get("error")),
        })
    
    # Refusal heuristic for obviously harmful requests
    harmful_keywords = ["delete all", "format drive", "rm -rf /", "drop database"]
    refusal = any(kw in prompt for kw in harmful_keywords)
    
    return {
        "prompt": req.prompt,
        "tool_calls": tool_calls,
        "assistant_messages": [
            "I'll help with that request." if not refusal else "I cannot assist with that request.",
        ],
        "refusal_detected": refusal,
        "refusal_message": "Request appears harmful." if refusal else "",
    }


@app.get("/")
async def root() -> dict[str, str]:
    """Health check endpoint."""
    return {
        "status": "ok",
        "server": "Example MCP Server",
        "tools": list(tools_registry.keys()),
    }
