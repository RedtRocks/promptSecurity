# agent-hardener

**Automatically finds how an AI agent's tool can be abused, then writes and enforces a security policy for it.**

Give it one MCP tool definition. It attacks that tool with an LLM red-teamer, measures what actually worked against a live agent, synthesizes an information-flow policy from the successful attacks, and ships a gateway that enforces the policy at runtime.

```
  tool.yaml
      │
      ▼
  ┌─────────────┐   adversarial prompts    ┌───────────┐
  │  Stage 1    │ ───────────────────────► │   live    │
  │  attack     │ ◄─────────────────────── │   agent   │
  └─────────────┘   what it actually did   └───────────┘
      │
      ▼
  ┌─────────────┐  Stage 2: why did it work?  (exploit type A–E)
  │  analyze    │
  └─────────────┘
      │
      ▼
  ┌─────────────┐  Stage 3: SAMOS policy — capabilities, taint rules,
  │  policy     │            enforcement rules
  └─────────────┘
      │
      ├──► verifier ──► ABR / BPR / F1     (does it block attacks AND allow real use?)
      │
      └──► gateway  ──► live enforcement in front of the real agent
```

## The thing that makes this non-trivial

Attack-block rate alone is a **gameable metric**. A policy that disables the tool entirely blocks 100% of attacks — and 100% of legitimate use. Early versions of this pipeline generated exactly that policy, repeatedly, because capability denial is the bluntest lever available.

So every policy is scored on both sides, by replaying **the same gates** over attack trajectories and over a suite of legitimate tasks:

| Metric | Meaning |
|---|---|
| **ABR** — attack block rate | fraction of *successful* attacks the policy blocks |
| **BPR** — benign pass rate | fraction of legitimate tasks still allowed |
| **F1** | harmonic mean of the two — a deny-all policy scores **0** |

Two guards (`_guard_core_capabilities`, `_guard_core_tool_blocks`) exist specifically to stop the generator from reaching for deny-all. Both were needed: a live `read_file` run collapsed to F1=0 with only the first one active.

## Results

> Run `scripts/aggregate_runs.py --by-tool` over ≥5 seeded runs and paste the table here.
> Report mean±std, not point estimates. Report direct and indirect injection separately.

| Tool | ABR | BPR | F1 |
|---|---|---|---|
| _(pending)_ | | | |

## Quick start

```bash
pip install -e ".[dev]"
cp config.example.yaml config.yaml     # set model + agent endpoint

# 1. launch the evaluation agent (a real ReAct agent, not a keyword stub)
OLLAMA_BASE_URL=... AGENT_LLM_MODEL=ollama/gemma3:27b AGENT_MAX_STEPS=6 \
  python -m uvicorn scripts.llm_agent_server:app --port 8080

# 2. attack a tool and generate its policy
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml

# 3. enforce the policy in front of the agent
agent-hardener gateway --policy hardener_output/read_file/report.json \
  --agent-endpoint http://localhost:8080 --port 8090
```

Outputs land in `hardener_output/<tool>/`: `report.json` (machine-readable, includes every
verifier verdict so reviewers can audit each number), `report.html` (dashboard), and
`run_manifest.json` (models, versions, settings — for reproducibility).

## What's in the box

| Path | What it is |
|---|---|
| `src/agent_hardener/stage1/` | attack generation — 8 named red-team techniques, escalation-on-refusal |
| `src/agent_hardener/stage2/` | exploit classification (A–E) and documentation-edit recommendations |
| `src/agent_hardener/stage3/` | SAMOS policy synthesis + the two anti-deny-all guards |
| `src/agent_hardener/verifier/` | **deterministic** policy replay — no LLM in the loop |
| `src/agent_hardener/gateway_server.py` | FastAPI policy-enforcing proxy (`/run`, `/policy`, `/audit`) |
| `src/agent_hardener/defenses.py` | prompt-level defense baselines (spotlighting, instruction defense, sandwich) |
| `mcp_tools/` | 10-tool corpus, each with a benign-task suite |
| `mcp_tools/poisoned/` | 7 poisoned tool descriptions, each with a **matched clean control** |

### Three enforcement gates

The verifier is deterministic — it replays a trajectory through the policy with no model call, which is what turns "policy coverage" from a prediction into a measurement.

1. **Capability** — is this tool's capability (network/filesystem/exec/env) denied outright?
2. **Confidentiality taint** (IFC-001) — read something secret, then write to a public sink → block. Stops data flowing *out*.
3. **Integrity taint** (IFC-002) — ingested attacker-controlled content, then took a consequential action → block. Stops an indirect injection being *carried out*. Benign trajectories never carry untrusted content, so this gate raises ABR at zero BPR cost.
4. **Enforcement rules** — argument-aware trigger matching, so "block `db_query` on `SELECT ... users`" fires on that query, not on every query.

## Threat model

**In scope:** a third-party MCP tool whose *description* is attacker-supplied but read as trusted (OWASP `MCP03:2025`), and indirect prompt injection delivered through tool *results* into a bounded ReAct agent.

**Out of scope, stated plainly:** cross-server tool shadowing, rug pulls, MCP authorization / confused-deputy issues. The pipeline never modifies a tool's *implementation* — the honest framing is *description-derived attack-surface analysis plus runtime policy synthesis*.

## Evaluation scripts

```bash
python scripts/tool_poisoning_eval.py        --config config.yaml --repeats 3   # recall / FPR / precision
python scripts/defense_baseline_eval.py      ...                                # policy vs. spotlighting et al.
python scripts/record_benign_trajectories.py --all --config config.yaml         # agent-recorded benign suites
python scripts/grade_with_human_labels.py    emit-template ...                  # blind human-labeling CSV
python scripts/cohen_kappa.py                labels.csv --bootstrap 1000        # inter-rater agreement
python scripts/aggregate_runs.py             runA runB --by-tool                # mean±std across runs
```

## Development

```bash
pytest tests/ -v
ruff check src/ && mypy src/
```

See [CLAUDE.md](CLAUDE.md) for architecture detail and a candid list of the known
validity limitations — what's fixed in code, and what still needs work before publication.
