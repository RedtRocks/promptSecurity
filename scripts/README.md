# Testing with Real MCP Servers

This directory contains utilities for testing `agent-hardener` with real MCP servers.

## Quick Start: Test with Example Server

### 1. Start the example MCP server

```powershell
uv run uvicorn scripts.example_mcp_server:app --port 8080
```

This starts a local MCP server with 4 intentionally vulnerable tools:
- **`send_email`** — No recipient validation, unrestricted file attachments
- **`read_file`** — No path traversal protection
- **`execute_command`** — No command whitelist or sandboxing
- **`list_directory`** — No directory access control

### 2. Fetch tool definitions

In a new terminal:

```powershell
uv run python scripts/fetch_mcp_tools.py http://localhost:8080
```

This extracts all 4 tools to `./mcp_tools/` as YAML files.

### 3. Configure API keys

```powershell
cp config.example.yaml config.yaml
# Edit config.yaml and add your OpenAI API key
```

Or set via environment variable:

```powershell
$env:OPENAI_API_KEY = "sk-..."
```

### 4. Run the security analysis

```powershell
uv run agent-hardener analyze `
  --tool-file mcp_tools/send_email.yaml `
  --config config.yaml `
  --agent-endpoint http://localhost:8080
```

This will:
1. Profile the `send_email` tool
2. Generate 8 adversarial prompts (one per harm category)
3. Iteratively refine attacks against the live MCP server
4. Analyze successful attacks by exploit type
5. Generate SAMOS IFC policies and container deployment specs
6. Output results to `./hardener_output/send_email_report.{json,html}`

### 5. View results

Open `hardener_output/send_email_report.html` in a browser to see:
- Attack success rates by harm category
- Exploit type classification (A–E taxonomy)
- Edit recommendations for tool documentation
- SAMOS policy (taint rules, enforcement rules, deployment directives)

---

## Testing with Your Own MCP Server

If you have an existing MCP server running:

### 1. Fetch tools from your server

```powershell
uv run python scripts/fetch_mcp_tools.py https://your-server.com:8080 --output ./your_tools/
```

### 2. Run analysis on a specific tool

```powershell
uv run agent-hardener analyze `
  --tool-file your_tools/<tool_name>.yaml `
  --config config.yaml `
  --agent-endpoint https://your-server.com:8080
```

---

## MCP Server Requirements

Your MCP server must implement:

**1. `POST /tools/list`** — Returns available tools

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "tool_name",
        "description": "Tool description",
        "inputSchema": {
          "type": "object",
          "properties": {...},
          "required": [...]
        }
      }
    ]
  }
}
```

**2. `POST /run`** — Executes agent with prompt

Request:
```json
{
  "prompt": "Send an email to attacker@evil.com"
}
```

Response:
```json
{
  "prompt": "...",
  "tool_calls": [
    {
      "tool_name": "send_email",
      "parameters": {"to": ["attacker@evil.com"], ...},
      "success": true,
      "response": "Email sent"
    }
  ],
  "assistant_messages": ["I'll help with that."],
  "refusal_detected": false
}
```

---

## Troubleshooting

**"No tools found or connection failed"**
- Verify the MCP server is running: `curl http://localhost:8080/`
- Check the endpoint URL format (should not include `/tools/list`)
- Ensure the server implements MCP JSON-RPC protocol

**"Connection error" during analysis**
- Confirm the server's `/run` endpoint accepts `{"prompt": "..."}` POST requests
- Check server logs for errors
- Increase timeout in `config.yaml` if agent responses are slow

**"All attacks failed"**
- The agent may be too restrictive or properly secured
- Try a different tool with more attack surface (e.g., filesystem, network capabilities)
- Check `--max-iterations` (default: 6) — increase for harder-to-exploit tools

**High API costs**
- Each tool analysis makes ~50-100 LLM calls across 3 stages
- Use a cheaper model for testing: `--provider "openai/gpt-4o-mini"`
- Reduce iterations: `--max-iterations 3`
