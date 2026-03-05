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
```

## Configuration

Copy `config.example.yaml` and set your API keys and agent endpoint:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
agent-hardener analyze --tool-file tool.yaml --config config.yaml
```

## Output

Results are written to `./output/` (configurable) as:
- `<tool_name>_report.json` — full machine-readable report
- `<tool_name>_report.html` — interactive dashboard with Chart.js visualisations

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
