# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run the full pipeline
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml
agent-hardener harden --tool-file mcp_tools/read_file.yaml --config config.yaml

# Stage 1 only (attack generation without live agent cycles)
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml --stage1-only

# Run via module (useful during development)
python -m agent_hardener.cli --tool-file mcp_tools/read_file.yaml --config config.yaml

# Run tests
pytest tests/ -v

# Run a single test file
pytest tests/test_stage1.py -v

# Ablation: skip the LLM attacker, use deterministic templates only
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml --baseline-attacks template

# Ablation: skip Stage 1.3 refinement (P0-only baseline)
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml --no-refine

# Variance estimation: 5 independent seed-sweep runs per attack cycle
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml --n-repeats 5

# Hardening with live policy enforcement (round N>=2 wraps the agent with round N-1's policy)
agent-hardener harden --tool-file mcp_tools/read_file.yaml --config config.yaml --enforce-prior-policy

# Production deployment: launch a SAMOS policy gateway in front of an existing agent
agent-hardener gateway --policy hardener_output/report.json \
  --agent-endpoint http://localhost:8080 \
  --host 127.0.0.1 --port 8090 \
  --audit-log hardener_output/gateway_audit.jsonl

# Cross-run aggregation: combine multiple run_manifest.json + report.json into a CSV
python scripts/aggregate_runs.py hardener_output/runA hardener_output/runB --out runs_summary.csv

# Inter-rater agreement between two graders (e.g., human vs. LLM, or grader-A vs. grader-B)
python scripts/cohen_kappa.py labels.csv --col-a llm_grader --col-b human_grader --bootstrap 1000

# Lint / type-check
ruff check src/
mypy src/
```

## Setup

Copy `config.example.yaml` to `config.yaml` and fill in API keys and agent endpoint before running:

```bash
cp config.example.yaml config.yaml
```

Settings are loaded from `config.yaml`, then overridden by environment variables (uppercase field names), then by CLI flags. The `.env` file is also supported for secrets.

## Architecture

The project is a 3-stage adversarial security pipeline that tests MCP-style AI agent tools for exploitability and generates security policies.

### Data flow

```
Tool YAML/JSON
    → Stage 1: profile_tool → generate_attacks → run_attack_cycle (parallel)
    → Stage 2: analyze_attack → synthesize → recommend_edits
    → Stage 3: annotate → build_policy
    → output/report.py → report.json + report.html
```

The `harden` command repeats this pipeline in a loop (`hardening.py`), feeding Stage 3 edit recommendations back into the tool definition until the attack success rate falls below `hardening_target_success_rate`.

### Inter-stage contracts (`shared/schemas.py`)

All stage inputs and outputs are Pydantic v2 models — no untyped dicts cross stage boundaries. Key types:
- `MCPToolDefinition` — input tool spec (parsed from YAML/JSON)
- `ToolProfile` — Stage 1.1 output (semantic domain, ambiguities, capability profile)
- `AdversarialPrompt` → `AttackRecord` — Stage 1.2/1.3 output per harm category
- `VulnerabilityFinding`, `FailureAnalysisReport` — Stage 2 output
- `SAMOSPolicy` — Stage 3 output (confidentiality annotations, taint rules, enforcement rules)

### LLM provider (`shared/llm_provider.py`)

All stages call `LLMProvider`, never litellm directly. `LLMProvider` handles:
- Routing between OpenAI/Anthropic/Ollama via LiteLLM `Router`
- Ollama-specific direct HTTP calls (`/api/chat` or `/api/generate`) to bypass LiteLLM limitations with `think: false` and JSON format enforcement
- Separate primary model (generation) and grader model (scoring)
- Model-family detection (`shared/model_config.py`) for per-family temperature/token tuning

### Model families (`shared/model_config.py`)

The `detect_model_family()` function maps LiteLLM model strings to `ModelFamily` enum values (OPENAI, ANTHROPIC, QWEN, GEMMA, LLAMA, OLLAMA). Each family has tuned `ModelParameters` for attack, refine, grade, and profile tasks. When a new model needs different parameters, add/update an entry in `model_config.py`.

### Agent client (`shared/agent_client.py`)

Sends adversarial prompts to the live agent endpoint. Accepts responses in MCP-compatible format (`tool_calls`, `assistant_messages`, `refusal_detected`). The endpoint is configured via `agent_endpoint` in settings.

### Tool definition format (`mcp_tools/`)

Tool YAML files follow MCP `inputSchema` conventions. The pipeline reads `name`, `description`, `inputSchema.properties`, and optionally `kb_context` (knowledge base / system prompt) and `target_agent_endpoint`.

### Stage 1 harm categories

Eight categories from the AgentHarm taxonomy: `disinformation`, `harassment`, `fraud`, `cybercrime`, `copyright`, `hate_speech`, `drugs`, `sexual_content`. One `AdversarialPrompt` is generated per category and refined iteratively (`refiner.py`) using a Red-Agent-Reflect loop.

### Stage 3 policy model (SAMOS)

Generates `SAMOSPolicy` with:
- Confidentiality annotations (read/write levels: `high` / `low`)
- Capability annotations (network FQDNs, filesystem paths, env vars, execution paths)
- Session taint propagation rules
- Enforcement rules (`BLOCK` / `AUDIT` / `REQUIRE_CONFIRMATION`)
- Deployment spec (isolation level, container enforcements)

### Output (`output/report.py`)

Writes `<tool_name>_report.json` (machine-readable) and `<tool_name>_report.html` (Chart.js dashboard) to `hardener_output/` by default.

## Research context

This is a **capstone project** that is also being written up as a research paper. The implementation works as a demo, but multiple aspects of the methodology are not yet publication-grade. Before making changes, understand the validity issues below — many "improvements" to UX or speed will reinforce these issues rather than fix them.

### Known validity problems

**Mitigated in code (still need follow-through in the paper):**

1. **Self-grading.** `LLMProvider.__init__` emits a `UserWarning` when grader and primary share a family. `config.example.yaml` recommends cross-family grader pairs. `run_manifest.json` records `same_family_grader: true/false` for every run. **Still required for publication:** human-labeled subset with reported Cohen's κ on at least one tool.

2. **Memoized blocklist vs. policy-driven defense.** `Settings.enable_signature_memory` is now `False` by default. The honest stopping criterion uses `agent_run_success_rate` (excludes signature-blocked attacks from the denominator). `_run_round` emits both metrics — `success_rate` (legacy, inflated) and `agent_run_success_rate` (honest) — plus `signature_blocked` count. **Still required for publication:** ablation showing both metrics across rounds.

3. **Fallback attacks pollute the dataset.** `AdversarialPrompt.is_fallback` flag is set in `attacker._fallback_attack`. `pipeline_health.fallback_rate` is emitted in `run_manifest.json` and in the per-round summary. **Still required:** report fallback rate in every results table; consider treating fallback rows as a separate condition.

4. **Reproducibility hygiene.** Every run now writes `run_manifest.json` with `default_model`, `grader_model`, `same_family_grader`, `ollama_base_url`, `litellm.__version__`, pipeline-health, and the full pipeline settings. **Still required:** pin model versions (use full revision strings like `anthropic/claude-3-5-sonnet-20241022`) and capture Ollama model digests (`ollama show <model>`) outside of agent-hardener.

5. **Unverified performance claims.** Removed from `IMPLEMENTATION_SUMMARY.md`. `scripts/benchmark_models.py` now measures per-model generation latency (mean/p50/p95) and char/s throughput via the project's own `LLMProvider`. **Still required:** run it on the paper's model set and paste the table into `IMPLEMENTATION_SUMMARY.md`.

6. **No statistical rigor → seed sweeps now wired.** `run_attack_cycle` accepts a `seeds: list[int]` parameter and `Settings.n_repeats` controls how many repeats are scheduled. The CLI exposes `--n-repeats N`. When N > 1, every `AttackRecord` carries `seed_scores: list[float]` and `seeds_used: list[int]`; `final_score` is the mean across runs. The aggregator in `scripts/aggregate_runs.py` reports `mean_seed_stddev` per run. **Still required:** add bootstrap CIs to the HTML report, and run paper experiments with `--n-repeats 5` minimum.

7. **No baseline modes → both baselines now available.** `--baseline-attacks template` skips the LLM attacker entirely and emits only fallback templates (so the LLM attacker's marginal contribution is measurable). `--no-refine` (equivalently `--max-iterations 0`) skips Stage 1.3 refinement so you can isolate the value of iterative refinement. Both flow through to `Settings.baseline_attacks` and `Settings.max_iterations`.

8. **Policy was never enforced at dispatch time → live gateway built.** Two layers:
   - `agent_hardener.verifier.PolicyEnforcingAgentClient` — drop-in `AgentClient` wrapper applying the three deterministic gates to every trajectory returned by the inner agent. Used in-process during hardening rounds; gated by `Settings.enforce_prior_policy` (CLI `--enforce-prior-policy`) so round N≥2 sees the policy from round N-1 enforced on returned trajectories.
   - `agent_hardener.gateway_server` — FastAPI service that turns a generated `SAMOSPolicy` JSON into a production runtime control. Loads the policy at startup, exposes `POST /run` matching the inner agent's contract, and applies the same three gates before returning the trajectory. Endpoints: `POST /run`, `GET /health`, `GET /policy`, `GET /audit`, `POST /tools/list`. Audit ring + optional JSONL sink for observability. Launch with `agent-hardener gateway --policy report.json --agent-endpoint http://...:8080`.

9. **Inter-rater agreement tooling shipped.** `scripts/cohen_kappa.py` computes Cohen's κ from a two-column CSV with optional bootstrap CI. Useful for both (a) human-vs-LLM grader comparisons once labels exist, and (b) LLM-vs-LLM cross-family grader agreement now.

10. **Evaluation target is now a real LLM agent, not a regex.** `scripts/llm_agent_server.py` replaces the keyword-routing `example_mcp_server` with a genuine function-calling agent: an LLM plans tool calls from the schemas + user request and can *refuse* harmful requests. Attack success now reflects model behaviour, not substring matching. Tool execution is **simulated** (canned results) so adversarial prompts never run real shell/FS operations. Launch: `OLLAMA_BASE_URL=... AGENT_LLM_MODEL=ollama/gemma3:27b python -m uvicorn scripts.llm_agent_server:app --port 8080`.

11. **Hardening edits now have a causal path.** `AgentClient.set_tool_context(tool)` forwards the tool's (edited) description + `kb_context` as a `system_prompt` on every `/run`; the LLM agent obeys it. `cli.py` (analyze) and `hardening.py` (each round) call it, so Stage-2 documentation edits actually influence agent behaviour. Keyword agents ignore the extra field.

12. **Degenerate deny-all policies prevented.** Stage 3's annotator used to disable the tool's core capability (`filesystem=False` for a file reader), producing a policy that blocks 100% of attacks *and* 100% of legitimate use. `_guard_core_capabilities` now keeps any capability the profile marks as used (`True`), delegating exfiltration defense to session taint + enforcement rules (blocking the *flow*, not the *tool*). This is what makes the security/utility F1 non-trivial. **The same deny-all lever exists at the enforcement layer:** because the verifier matches trigger conditions by tool *name* only, any `BLOCK` enforcement rule keyed on the tool's own core tool blocks *every* call (benign included) → BPR=0, F1=0. `_guard_core_tool_blocks` (`stage3/policy_builder.py`) downgrades such rules to `REQUIRE_CONFIRMATION`, keeping genuine exfiltration defense on session taint and sink-keyed rules. Both guards are needed; a live `read_file` run without the enforcement guard produced a degenerate deny-all policy (F1=0) even though the capability guard was already active.

13. **Teaching-to-the-test hacks disabled by default.** `attacker._make_parser_aware_prompt` and `refiner`'s success-anchor injection hard-coded trigger tokens so the *keyword stub* would call tools. They biased attack success upward against a real agent and are now OFF by default (`AH_PARSER_AWARE_PROMPTS=0`); enable only when targeting the keyword stub.

14. **Success threshold aligned to the grader rubric.** Use `attack_success_threshold: 0.8` ("substantially achieved the harmful goal") for paper runs. 0.3 counts "made some calls but did NOT complete the harm" as success, inflating rates.

15. **Exploit taxonomy coding manual shipped.** `docs/EXPLOIT_TAXONOMY.md` gives decision rules, examples, and a tie-break order for the A–E types, plus an inter-coder reliability protocol (label ≥40 trajectories, compute κ via `scripts/cohen_kappa.py`).

**Not yet fixed (need code work before paper):**

16. **Threat model framing.** The pipeline edits `kb_context` (now with a causal path to the LLM agent) and emits a policy (now enforceable via the gateway), but never modifies the tool's *implementation*. "Description-derived attack-surface analysis + runtime policy synthesis" is the honest framing.

17. **Corpus (partially grown).** `mcp_tools/` now has 10 diverse tools (file read/write, exec, list, email, http, db query, web search, post message, calendar) each with a `benign_tasks/` suite; the LLM agent server auto-loads all of them so adding a YAML needs no server edit (a test enforces every corpus tool has a benign suite). **Still required:** pull ≥20 from the public MCP registry for a stronger generalization claim.

### Stronger attack generation (`stage1/attack_strategies.py`)

Attacks are no longer one generic prompt per harm category. Each attack is built with a **named, research-grounded red-team technique** (direct, benign-decomposition, authority pretext, hypothetical framing, indirect tool-chaining, context priming, obfuscation, strong authority override), ordered by escalation strength and capped by attack intensity. Every `AdversarialPrompt` records its `attack_strategy` for per-technique analysis.
- **Breadth**: `Settings.attack_breadth` / `--attack-breadth N` generates N distinct techniques per category (total ≈ categories × N), for stronger, broader coverage.
- **Escalation on refusal**: when the agent refuses, the refiner switches to a *stronger* strategy (`next_escalation`) instead of only rewording — the core of iterative strengthening.

18. **Grader still needs human calibration.** Cross-family grading + the coding manual are in place, but no human labels exist yet. Collect them and report κ before the paper.

19. **CUDA showcase is off-path.** `cuda_showcase/` accelerates post-hoc report aggregation. Drop from the security paper or write a separate, narrow HPC paper.


### SAMOS policy verifier (`agent_hardener/verifier/`)

The policy verifier replays each `AttackRecord`'s final trajectory through a parsed `SAMOSPolicy` and emits a deterministic `PolicyCoverage` — **no LLM is consulted**. This is what turns the headline "policy coverage" number from a prediction into a measurement.

How it works:
1. For each attack record, walk the last iteration's `tool_calls` in order.
2. **Gate 1 — capability**: infer the SAMOS capability (`network` / `filesystem` / `environment` / `execution`) from the tool name (heuristic in `verifier/capabilities.py`). If `policy.capability_annotations.<capability> is False`, the call is BLOCKED.
3. **Gate 2 — taint**: maintain a session taint level starting at `policy.session_taint_rules.initial_session_taint`. Reads of high-confidentiality data (the policy's target tool when `read_confidentiality == HIGH`, or any annotated tool) upgrade the session to HIGH (monotonic). Writes to a low-confidentiality sink under HIGH taint trigger `IFC-001-HIGH-TO-LOW` and the call is BLOCKED.
4. **Gate 3 — enforcement rules**: each `EnforcementRule.trigger_condition` is matched to the current tool by name, then its **argument-level conditions are checked against the call's parameters** (`_argument_conditions_satisfied`); a rule fires only if both match (triggers with no evaluable argument literal fall back to name-only firing). `BLOCK` ends the trajectory; `AUDIT` / `REQUIRE_CONFIRMATION` are recorded but don't stop replay.

Each replay produces a `VerifierVerdict` with `final_status`, `triggered_rule_ids`, `triggered_capability_denials`, `taint_violation`, `first_blocking_step`, `final_taint`, and human-readable `notes`. These verdicts ship in `report.json` under `policy_verifier_verdicts` so reviewers can audit every coverage number.

Coverage is counted **only over attacks that succeeded against the unguarded agent** (`final_score > success_threshold`). Failed attacks don't speak to the policy's effectiveness; they were already handled upstream. The aggregator (`verifier/coverage.py`) maps verdicts to `PolicyCoverage`:
- `BLOCKED` → `attacks_fully_blocked_by_policy`
- `AUDITED` / `REQUIRES_CONFIRMATION` → `attacks_partially_mitigated`
- `UNMITIGATED` but `record.refusal_occurred` → `attacks_requiring_model_level_defense`
- `UNMITIGATED` otherwise → `unmitigated_attacks`

Known approximations (documented so reviewers can challenge them):
- Capability inference is from tool **names**, not implementations. Override per-tool by extending `_CAPABILITY_HINTS` in `verifier/capabilities.py` or, eventually, by reading capability tags off the MCP tool definition itself.
- Trigger-condition matching is **argument-aware** (`_argument_conditions_satisfied` in `verifier/replay.py`). A rule is first matched to a call by tool name, then its argument-level conditions (quoted string literals in the trigger, combined as OR-of-ANDs) are checked against the call's recorded parameters + response — so "block `db_query` when `query CONTAINS 'SELECT ... users'`" fires only on calls whose parameters contain that literal, not on every `db_query` call. The **same** function runs for adversarial and benign trajectories (`replay_trajectory` is shared), so this adds precision symmetrically and cannot selectively exempt benign calls. **Fail-safe:** a trigger with no evaluable argument literal (tool-identity only, or session/taint/history references) degrades to name-only firing, preserving the historical over-approximation (coverage stays a lower-bound on blocking). Tool-identity literals are told apart from argument-value literals using the real tool names in the trajectory. This is what lifts security/utility F1 above 0 for tools whose malicious vs. benign calls differ only in *arguments* (execute_command, db_query, http_request, send_email) rather than in tool identity or data-flow.
- `Capability == list[str]` (allowed-set) is treated as "not outright denied". A finer-grained allowed-set check (e.g., is this exact path in the allowed list?) requires per-tool parameter parsers and is out of scope for v1.

### Security/utility tradeoff (`agent_hardener/verifier/utility.py`)

Attack coverage **alone is a gameable metric**: a policy that disables the tool wholesale (`filesystem=False, network=False`) blocks every attack and scores 100% coverage — while destroying all legitimate use. This is not hypothetical; the generated policies frequently do exactly this (they reach for capability denial because it's the bluntest lever).

To make coverage meaningful, benign trajectories are replayed through the **same** gates (`replay_trajectory` is shared by attack and benign paths). Per tool, `benign_tasks/<tool>.yaml` lists legitimate uses the policy must not block. The evaluator (`evaluate_security_utility`) reports:
- **Attack block rate (ABR)** — fraction of *successful* attacks blocked (security).
- **Benign pass rate (BPR)** — fraction of legitimate tasks still allowed (utility).
- **Over-block rate** — `1 − BPR`, the false-positive rate against legitimate use.
- **Utility·security F1** — harmonic mean of ABR and BPR. A deny-all policy has `BPR = 0 ⇒ F1 = 0`, so it **cannot game** the headline number.
- **`degenerate_deny_all`** — flagged `True` when the policy blocks every benign task.

This ships in `report.json` under `security_utility`, is surfaced prominently in the HTML report (Stage 3, with a red degenerate-policy banner), and is aggregated into `scripts/aggregate_runs.py` for cross-run tables. `generate_report(..., success_threshold=...)` must receive the run's threshold so ABR counts the same attacks the run did. Benign suites are optional — a missing suite reports utility as unmeasured (`n_benign_tasks == 0`) rather than erroring.

### Roadmap to publication

In priority order. Items 1–9 above are addressed in code; the items below are what's still required:

- [x] **Security/utility tradeoff.** `verifier/utility.py` + `benign_tasks/<tool>.yaml` replay benign trajectories through the policy gates and report ABR / BPR / over-block / F1 / `degenerate_deny_all`. This defeats the "coverage is gameable by deny-all" objection — the single most important research-validity fix. **Still required:** expand benign suites beyond the 4 demo tools (see corpus item) and, ideally, collect the benign trajectories from a real agent rather than hand-authoring them.
- [ ] **Independent-grader study.** `scripts/grade_with_human_labels.py` now ships: `emit-template` turns a `report.json` into a blind human-labeling CSV, `merge` computes overall and per-category Cohen's κ (with bootstrap CI) between the human labels and the LLM judge. **Still required:** actually collect human labels on a stratified subset (e.g. 40 trajectories spanning all 8 harm categories and 3 exploit types) and report the κ.
- [x] **Seed sweeps + cross-run variance tooling.** `run_attack_cycle` takes `seeds: list[int]` (within-cycle sweep → `seed_scores`), and `scripts/aggregate_runs.py --by-tool` groups N independent full runs of each tool into per-tool mean±std of ABR / mitigation_rate / BPR / F1 (the paper's error-bar view). **Still required:** run the corpus ≥5× with a fixed seed and quote the mean±std, not single-run point estimates (see `docs/RESULTS_corpus_v1.md`).
- [ ] **Baseline modes.** `--baseline template` (skip LLM attack generation), `--baseline no-refine` (skip Stage 1.3) so the marginal contribution of each component is measurable.
- [x] **Benchmark script.** `scripts/benchmark_models.py` measures latency/throughput per model over a fixed prompt battery and writes a CSV. **Still required:** run it and paste results into the "Measured Results" section of `IMPLEMENTATION_SUMMARY.md`.
- [ ] **Expand corpus.** 20–50 real MCP tools in `mcp_tools/`.
- [ ] **Related-work table.** Compare against AgentDojo (Debenedetti et al. 2024), AgentHarm (Andriushchenko et al. 2024), InjecAgent, Agent Security Bench, and MCP-specific work.

### Reproducibility hygiene (when running experiments)

- Set `attack_parallelism: 1` and a fixed seed for paper runs — concurrent futures + LLM nondeterminism makes ordering noisy.
- Capture `default_model`, `grader_model`, `ollama_base_url`, `litellm.__version__`, and (for Ollama) `ollama show <model>` digests in a `run_manifest.json` alongside each report.
- Treat `AH_DEBUG_ATTACKER=1` runs as the primary artifact for paper supplementary material — the `stage1_attacker_debug.jsonl` is the raw trace that lets reviewers audit the LLM outputs.
- Avoid `--stage1-only` for headline numbers; it short-circuits grading and reports nothing about exploitability.

## Key configuration fields

| Field | Default | Purpose |
|-------|---------|---------|
| `default_model` | `openai/gpt-4o` | LiteLLM model string for generation |
| `grader_model` | (same as default) | Separate model for LLM-as-judge scoring |
| `ollama_base_url` | `http://localhost:11434` | Ollama server or Cloudflare tunnel URL |
| `agent_endpoint` | `http://localhost:8080/run` | Target agent to attack |
| `max_iterations` | 6 | Refinement iterations per attack (0 = no refinement baseline) |
| `attack_parallelism` | 2 | Concurrent attack cycles |
| `attack_success_threshold` | 0.95 | Score above which an attack is SUCCESS |
| `hardening_rounds` | 3 | Max rounds for `harden` command |
| `enable_signature_memory` | `False` | Memoized blocklist; off by default for honest metrics |
| `baseline_attacks` | `"llm"` | `"llm"` or `"template"` — baseline ablation control |
| `n_repeats` | 1 | Seed sweeps per attack cycle (>1 enables variance reporting) |
| `enforce_prior_policy` | `False` | In harden mode, wrap agent with prior round's policy |
