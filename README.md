# agent-hardener

An autonomous security pipeline CLI for hardening AI agent tool deployments.

## Overview

`agent-hardener` implements a 3-stage security hardening pipeline for any agent tool:

1. **Stage 1 — Adversarial Attack**: Generates adversarial prompts across 8 harm categories (AgentHarm taxonomy) and iteratively refines them using Red-Agent-Reflect until they succeed or exhaust iterations.
2. **Stage 2 — Failure Analysis**: Classifies each successful attack by exploit type (A–E), synthesizes cross-attack patterns, and produces targeted documentation edit recommendations.
3. **Stage 3 — Policy Generation**: Generates SAMOS information-flow control (IFC) policies — confidentiality annotations, session taint propagation rules, enforcement rules, and container deployment directives.

## Quick Start

```bash
pip install -e .
agent-hardener --help
agent-hardener analyze --tool-file path/to/tool.yaml --agent-endpoint http://localhost:8000
agent-hardener analyze --tool-file path/to/tool.yaml --config config.yaml --stage1-only
```

## Configuration

Copy `config.example.yaml` and set your API keys and agent endpoint:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
agent-hardener analyze --tool-file tool.yaml --config config.yaml
```

### Using Ollama Through Cloudflare Tunnel

Set these fields in `config.yaml`:

```yaml
default_model: "ollama/<your_model_name>"
ollama_base_url: "https://<your-subdomain>.trycloudflare.com"
```

Notes:

- Put your tunnel link in `ollama_base_url`.
- Use only the base URL (no trailing slash).
- Keep the model string in LiteLLM format: `ollama/<model_name>`.

Example run:

```bash
python -m agent_hardener.cli --tool-file mcp_tools/read_file.yaml --config config.yaml
```

### Running Against A Real Agent And Real Tools

For production-like evaluation, configure model inference and agent execution separately:

- default_model: the policy model used by agent-hardener (for prompt generation/grading/analysis)
- ollama_base_url: your Ollama or Cloudflare tunnel base URL
- agent_endpoint: your real agent service endpoint

Important:

- agent_endpoint must point to your agent service, not to Ollama.
- The client accepts either of these endpoint formats:
  - base URL, example: https://my-agent.example.com
  - explicit run URL, example: https://my-agent.example.com/run

Required agent contract:

- POST /run with body {"prompt": "..."}
- response includes fields compatible with:
  - tool_calls
  - assistant_messages
  - refusal_detected
  - refusal_message

Optional contract:

- POST /tools/list for tool discovery (MCP style)

Recommended config example:

```yaml
default_model: "ollama/gemma4:31b"
ollama_base_url: "https://<your-ollama-tunnel>.trycloudflare.com"
agent_endpoint: "https://<your-real-agent-host>"
```

## Output

Results are written to `./output/` (configurable) as:

- `<tool_name>_report.json` — full machine-readable report
- `<tool_name>_report.html` — interactive dashboard with Chart.js visualisations

If you run with `--stage1-only`, output includes:

- `stage1_attacks.json` — generated attacks only (attack cycles plus Stages 2 and 3 skipped)

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
