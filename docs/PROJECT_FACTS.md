# PROJECT_FACTS — Ground-Truth Repository Inventory

Generated from a full read of the repository at commit `05c4215` (branch `main`, clean
working tree apart from two untracked files noted in §2). Every claim below cites a
repo-relative path. Where something is **unknown or absent**, it is stated explicitly
rather than inferred.

---

## 1. Stack + Versions

### 1.1 Declared dependencies (`pyproject.toml`)

| Field | Value | Source |
|---|---|---|
| Package name | `agent-hardener` | `pyproject.toml:6` |
| Version | `0.1.0` | `pyproject.toml:7` |
| Python requirement | `>=3.10` | `pyproject.toml:10` |
| License | MIT (declared in metadata only — **no `LICENSE` file exists in the repo**) | `pyproject.toml:11` |
| Build backend | `hatchling>=1.26` | `pyproject.toml:1-3` |
| Console script | `agent-hardener = agent_hardener.cli:app` | `pyproject.toml:29-30` |
| Lint | `ruff`, line-length 100, target `py310` | `pyproject.toml:35-37` |
| Type-check | `mypy`, `strict = true`, `pydantic.mypy` plugin, python 3.10 | `pyproject.toml:39-43` |

Runtime dependencies (`pyproject.toml:13-24`), declared as **lower bounds only — nothing is
pinned in `pyproject.toml`**:
`litellm>=1.40`, `typer>=0.12`, `rich>=13.0`, `httpx>=0.27`, `pydantic>=2.5`,
`pydantic-settings>=2.2`, `pyyaml>=6.0`, `jsonschema>=4.20`, `jinja2>=3.1`, `mcp>=1.0`.

Dev extra (`pyproject.toml:26-27`): `pytest>=8.0`, `ruff`, `mypy`, `fastapi>=0.100`, `uvicorn>=0.20`.

**Undeclared but imported at runtime:** `requests` is imported by
`src/agent_hardener/shared/llm_provider.py:16` but is **not** listed in `pyproject.toml`
dependencies. It is only present transitively (via litellm). This is a real packaging bug.

### 1.2 Resolved versions (`uv.lock`, 592 KB, tracked)

| Library | Locked version |
|---|---|
| litellm | 1.81.16 |
| pydantic | 2.12.5 |
| pydantic-settings | 2.13.1 |
| typer | 0.24.1 |
| rich | 14.3.3 |
| httpx | 0.28.1 |
| jinja2 | 3.1.6 |
| jsonschema | 4.26.0 |
| mcp | 1.26.0 |
| pyyaml | 6.0.3 |
| requests | 2.32.5 |
| fastapi | 0.135.1 |
| uvicorn | 0.41.0 |
| openai | 2.24.0 |
| pytest | 9.0.2 |
| ruff | 0.15.2 |
| mypy | 1.19.1 |

Command used: `python` regex scan of `uv.lock` for `[[package]] name/version` pairs.

### 1.3 Languages / frameworks actually in the repo

- **Python** — sole implementation language (69 tracked `.py` files).
- **Jinja2 HTML template** — one file, `src/agent_hardener/output/templates/report.html.j2` (1,028 lines), which references Chart.js for the dashboard.
- **YAML** — 31 tracked files: tool definitions, benign suites, configs.
- **No** JavaScript/TypeScript build, no frontend framework, no database, no ORM, no migrations, no Docker/Compose file, no Makefile.
- Anthropic/OpenAI/Ollama are reached via **LiteLLM** (`shared/llm_provider.py`) plus direct HTTP for Ollama.

---

## 2. Directory Map

```
capstone/
├── src/agent_hardener/        Python package (the pipeline). 9,397 LOC.
│   ├── cli.py                 Typer CLI: analyze / harden / gateway commands
│   ├── hardening.py           Iterative multi-round hardening loop
│   ├── gateway_server.py      FastAPI runtime policy gateway
│   ├── defenses.py            Prompt-level defense baselines (data only)
│   ├── __main__.py            `python -m agent_hardener`
│   ├── shared/                Settings, schemas, LLM provider, agent client, manifest, model config
│   ├── stage1/                Profiler, attacker, attack strategies, grader, refiner
│   ├── stage2/                Analyzer, synthesizer, editor (documentation edits)
│   ├── stage3/                Annotator, policy_builder, deployment spec
│   ├── verifier/              Deterministic policy replay, coverage, utility, capabilities, gateway shim, benign loader
│   └── output/                report.py (JSON+HTML), live.py (terminal monitor), templates/
├── scripts/                   14 standalone research/eval scripts + README. 3,417 LOC.
├── tests/                     17 pytest modules + fixture. 3,988 LOC, 196 collected tests.
├── mcp_tools/                 10 MCP tool YAML definitions (the corpus)
│   └── poisoned/              7 poisoned variants + README (tool-poisoning detection set)
├── benign_tasks/              10 benign-task suites (one per corpus tool), 31 tasks total
├── docs/                      6 markdown docs (4 tracked, 2 untracked stubs)
├── hardener_output/           Generated run artifacts (gitignored; present locally, 20+ run dirs)
├── sample_report/             Pre-generated demo report.html/report.json
├── .vscode/                   Editor config (c_cpp_properties.json, launch.json, settings.json)
├── .claude/settings.local.json  Claude Code permission allowlist
├── CLAUDE.md                  Authoritative project/agent instructions (333 lines)
├── README.md                  Public overview (123 lines)
├── prompt.md                  819-line design/spec prompt document
├── IMPLEMENTATION_SUMMARY.md, MODEL_OPTIMIZATION_GUIDE.md, MODEL_OPTIMIZATION_README.md,
│   PROMPT_EXAMPLES.md, TEST_PROMPTS_CLI.md, RUN_PROJECT_INSTRUCTIONS.md
│                              — all present on disk but **gitignored** (`.gitignore:48-53`)
├── agent_hardener_usecase.drawio   The ONLY diagram artifact in the repo (14 KB draw.io XML, untrackedness: tracked)
├── config.example.yaml        Documented config template (146 lines)
├── config.yaml                Local secrets config (gitignored, present on disk)
├── config.run.yaml, config_demo_improvement.yaml   Additional run configs (tracked)
├── pyproject.toml, uv.lock
└── .gitignore
```

Untracked-but-present files (from `git status --porcelain -uall`):
`docs/FORMAT_SPEC.md`, `docs/MENTOR_EVAL_CHECKLIST.md` — both are **explicit "BLOCKED / NOT
FOUND" stubs** stating their source documents (`docs/inputs/`) do not exist
(`docs/FORMAT_SPEC.md:3-12`, `docs/MENTOR_EVAL_CHECKLIST.md:3-13`).

Cache/venv dirs present but ignored: `.venv/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`,
`pytest-cache-files-*` (3 dirs, unreadable — permission denied).

---

## 3. Module Inventory

### 3.1 `src/agent_hardener/` — top level

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `cli` | `src/agent_hardener/cli.py` (890 L) | Typer app with 3 commands: `analyze`, `harden`, `gateway`. Orchestrates the 3-stage pipeline, renders Rich progress/tables. | CLI flags, tool YAML/JSON, `config.yaml` | `report.json`, `report.html`, `run_manifest.json`, `stage1_attacks.json` (`--stage1-only`) | typer, rich, yaml, all stages, `output.report`, `shared.manifest` | Complete |
| `__main__` | `src/agent_hardener/__main__.py` (7 L) | `python -m agent_hardener` shim | argv | delegates to `cli.app` | cli | Complete |
| `hardening` | `src/agent_hardener/hardening.py` (773 L) | Multi-round attack→analyze→policy→edit loop; intensity ladder; learned-defense memory; honest vs. legacy success rates | `MCPToolDefinition`, `Settings`, `LLMProvider`, `AgentClient` | `hardening_history.json`, final report, manifest | all stages, verifier (optional), rich | Complete |
| `gateway_server` | `src/agent_hardener/gateway_server.py` (258 L) | FastAPI app factory wrapping `PolicyEnforcingAgentClient`; audit ring + JSONL sink | `SAMOSPolicy` (file or object), agent endpoint or inner agent | FastAPI app; JSON responses; audit JSONL | fastapi (optional import guard at `:41-47`), verifier | Complete |
| `defenses` | `src/agent_hardener/defenses.py` (140 L) | 5 prompt-level defense baselines as frozen dataclasses (`none`, `instruction`, `spotlighting`, `sandwich`, `sink_restriction`) | none (static data) | `PromptDefense` objects | dataclasses only | Complete (data-only; applied by `AgentClient.set_defense`) |

### 3.2 `src/agent_hardener/shared/`

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `schemas` | `shared/schemas.py` (640 L) | All Pydantic v2 inter-stage contracts (see §4) | dicts / MCP JSON | typed models | pydantic | Complete |
| `settings` | `shared/settings.py` (101 L) | `BaseSettings` config; YAML → env → CLI precedence via `from_yaml` | `config.yaml`, env, `.env` | `Settings` | pydantic-settings, yaml | Complete |
| `llm_provider` | `shared/llm_provider.py` (439 L) | Single LLM abstraction: LiteLLM `Router` for OpenAI/Anthropic; direct HTTP `/api/chat` and `/api/generate` for Ollama; `<think>` stripping; `/no_think` for Qwen; same-family grader `UserWarning` at `:56-65` | messages, model_alias, temp, max_tokens | assistant text | litellm, requests, model_config | Complete |
| `model_config` | `shared/model_config.py` (344 L) | `ModelFamily` enum (OPENAI/ANTHROPIC/QWEN/GEMMA/LLAMA/OLLAMA/UNKNOWN) + per-family `ModelParameters` and prompt suffixes | model string | family, params, prompt suffixes | dataclasses | Complete |
| `agent_client` | `shared/agent_client.py` (243 L) | HTTP client for the target agent; `AgentClientProtocol`; forwards `system_prompt` + `injections`; refusal-keyword heuristic at `:220-227`; `list_tools()` for MCP `tools/list` | prompt, injections, tool context | `AgentTrajectory` | httpx | Complete |
| `manifest` | `shared/manifest.py` (99 L) | Writes `run_manifest.json` (models, same-family flag, settings, pipeline health, environment) | Settings, records, prompts | `run_manifest.json` | litellm (version probe), model_config | Complete |

### 3.3 `src/agent_hardener/stage1/`

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `profiler` | `stage1/profiler.py` (273 L) | Stage 1.1 — LLM security profile of the tool + tool-poisoning detection (`injected_instructions`, `poisoning_suspected`); deterministic keyword fallback at `:188-227` | `MCPToolDefinition` | `ToolProfile` | LLMProvider | Complete |
| `attack_strategies` | `stage1/attack_strategies.py` (248 L) | 8 ranked direct red-team techniques + 2 indirect-injection techniques; `strategies_for`, `next_escalation`, `injection_strategies` | intensity, breadth | `AttackStrategy` list | schemas | Complete |
| `attacker` | `stage1/attacker.py` (826 L) | Stage 1.2 — generates one `AdversarialPrompt` per (category × strategy); 4-tier JSON parse recovery (`:381-432`); template fallback; injection payload synthesis | tool, profile, taxonomy, breadth, baseline mode | `list[AdversarialPrompt]` | LLMProvider, attack_strategies | Complete |
| `grader` | `stage1/grader.py` (180 L) | LLM-as-judge 0.0–1.0 score, `max(llm_score, heuristic_score)`; deterministic heuristic partial credit at `:146-180` | trajectory + grading criteria | float score | LLMProvider | Complete |
| `refiner` | `stage1/refiner.py` (604 L) | Stage 1.3 — P0→P1→P2..Pmax Red-Agent-Reflect loop, refusal escalation, seed sweeps, progress events | `AdversarialPrompt`, agent, llm | `AttackRecord` | grader, attack_strategies, agent client | Complete |

### 3.4 `src/agent_hardener/stage2/`

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `analyzer` | `stage2/analyzer.py` (181 L) | Stage 2.1 — classify each attack into exploit type A–E; short-circuits when `final_score <= 0.5` (`:96-104`) | `AttackRecord`, tool | `VulnerabilityFinding` | LLMProvider | Complete |
| `synthesizer` | `stage2/synthesizer.py` (158 L) | Stage 2.2 — cross-attack aggregation + LLM narrative; returns `CrossAttackSummary` (a plain class, **not** a Pydantic model) | records, findings | `CrossAttackSummary` | LLMProvider | Complete |
| `editor` | `stage2/editor.py` (193 L) | Stage 2.3 — one MODIFY/ADD/DELETE edit per successful-attack finding; assembles `FailureAnalysisReport` | tool, findings, records | `list[EditRecommendation]`, `FailureAnalysisReport` | LLMProvider | Complete |

### 3.5 `src/agent_hardener/stage3/`

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `annotator` | `stage3/annotator.py` (320 L) | Stage 3.1 — read/write confidentiality + capability allowed-sets; `_guard_core_capabilities` (`:220-246`) prevents deny-all | profile, stage2 report, records | `(ConfidentialityAnnotations, CapabilityAnnotations)` | LLMProvider | Complete |
| `policy_builder` | `stage3/policy_builder.py` (652 L) | Stage 3.2–3.4 — taint rules, enforcement rules, gateway spec; `_guard_core_tool_blocks` (`:304-349`); calls the deterministic verifier to fill `policy_coverage` (`:202-208`) | annotations, records, analysis | `SAMOSPolicy` | LLMProvider, deployment, verifier | Complete. **Note:** `_compute_coverage` at `:615-652` is dead code — never called; superseded by the deterministic verifier. |
| `deployment` | `stage3/deployment.py` (123 L) | Stage 3.5 — container enforcement directives + isolation level | `CapabilityAnnotations` | `DeploymentSpec` | schemas | Complete (static templates) |

### 3.6 `src/agent_hardener/verifier/`

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `replay` | `verifier/replay.py` (499 L) | The 4-gate deterministic replay engine (capability / confidentiality taint / integrity taint / enforcement rules); argument-condition evaluation and literal masking | trajectory, policy | `VerifierVerdict` | capabilities, schemas | Complete |
| `coverage` | `verifier/coverage.py` (78 L) | Aggregates verdicts into `PolicyCoverage` over successful attacks only | records, policy | `(PolicyCoverage, verdicts)` | replay | Complete |
| `utility` | `verifier/utility.py` (115 L) | ABR / BPR / over-block / mitigation rate / F1 / `degenerate_deny_all` | records, policy, benign suite | `SecurityUtilityReport` | coverage, replay | Complete |
| `capabilities` | `verifier/capabilities.py` (56 L) | Name-substring → SAMOS capability inference; `capability_is_denied` | tool name, annotations | capability label / bool | none | Complete (heuristic, documented as an approximation at `:5-8`) |
| `gateway` | `verifier/gateway.py` (192 L) | `PolicyEnforcingAgentClient` — in-process post-hoc enforcement wrapper; rewrites blocked calls, drops subsequent ones | inner agent, policy | rewritten `AgentTrajectory` + `last_enforcement_log` | replay (imports 4 private functions) | Complete |
| `benign_loader` | `verifier/benign_loader.py` (90 L) | Loads `benign_tasks/<tool>.yaml`; search order: explicit dir → cwd → repo root | tool name, optional dir | `BenignTaskSuite \| None` | yaml | Complete |

### 3.7 `src/agent_hardener/output/`

| Module | Entry file | Purpose | Inputs | Outputs | Dependencies | State |
|---|---|---|---|---|---|---|
| `report` | `output/report.py` (384 L) | Writes `report.json` + `report.html`; bootstrap proportion CIs (`:118-145`); headline metrics; chart data; hardening showcase | tool, records, analysis, policy | `(json_path, html_path)` | jinja2, verifier | Complete |
| `live` | `output/live.py` (247 L) | Thread-safe Rich live table driven by refiner progress events; cp1252-safe glyph selection | progress events | Rich renderable | rich | Complete |
| template | `output/templates/report.html.j2` (1,028 L) | HTML dashboard (Chart.js) | render context | HTML | — | Complete |

### 3.8 `scripts/` (14 scripts, all standalone)

| Script | Entry file | Purpose | Inputs | Outputs | Deps | State |
|---|---|---|---|---|---|---|
| adaptive attack eval | `scripts/adaptive_attack_eval.py` (181 L) | Runs the same battery unguarded vs. `PolicyEnforcingAgentClient`-guarded; bootstrap CIs + risk reduction | `--tool-file --config --policy --threshold --max-iterations --breadth --out` | JSON results | pipeline internals | Complete |
| run aggregator | `scripts/aggregate_runs.py` (247 L) | Flattens N `run_manifest.json` (+`report.json`) into a CSV; `--by-tool` mean±std | run dirs, `--out` | CSV | stdlib only | Complete |
| model benchmark | `scripts/benchmark_models.py` (159 L) | Latency mean/p50/p95 + char/s per model via project `LLMProvider` | `--config --models --runs --max-tokens --out` | table + CSV | LLMProvider | Complete (never run — no results committed) |
| Cohen's κ | `scripts/cohen_kappa.py` (169 L) | κ + % agreement + bootstrap CI from a 2-column CSV | csv, `--col-a --col-b --bootstrap --ci --seed` | stdout | stdlib only | Complete |
| defense baselines | `scripts/defense_baseline_eval.py` (290 L) | Same battery + benign suite under 5 prompt defenses + enforced policy | `--tool-file --config --policy --breadth --max-iterations --benign-dir --out` | JSON | defenses, verifier | Complete (never run — no results committed) |
| example MCP server | `scripts/example_mcp_server.py` (331 L) | Keyword-routing stub agent with 4 tools; **executes real `subprocess` and real file reads** in `execute_tool` | HTTP | JSON-RPC/trajectory | fastapi | Complete but deprecated as an eval target (`scripts/llm_agent_server.py:3-7`) |
| fetch MCP tools | `scripts/fetch_mcp_tools.py` (138 L) | Pulls `tools/list` from a live MCP server → YAML files | server URL, `--output` | tool YAMLs | typer, httpx | Complete |
| human-label study | `scripts/grade_with_human_labels.py` (218 L) | `emit-template` → blind labeling CSV; `merge` → overall/per-category κ | `report.json` / filled CSV | CSV, κ report | cohen_kappa | Complete (no labels collected) |
| LLM agent server | `scripts/llm_agent_server.py` (479 L) | The real evaluation target: bounded ReAct loop, simulated tools, injection planting | HTTP | trajectory JSON | fastapi, LLMProvider | Complete |
| record benign | `scripts/record_benign_trajectories.py` (193 L) | Re-records benign suites from a live agent; drops empty trajectories; marks `provenance: recorded` | `--tool/--all --config --corpus-dir --benign-dir --out-dir --agent-endpoint` | `benign_tasks_recorded/*.yaml` | AgentClient | Complete. **`benign_tasks_recorded/` does not exist in the repo** — never run/committed. |
| live MCP eval | `scripts/run_live_mcp_eval.py` (256 L) | Discovers tools from a server and runs the pipeline per tool (shells out to the CLI) | server URL, `--config` | per-tool reports | typer, subprocess | Complete |
| repeated eval | `scripts/run_repeated_eval.py` (325 L) | Outer repeat loop over `run_live_mcp_eval` with aggregate stats | server URL, `--config --repeats` | summary JSON | typer, subprocess | Complete |
| sample report | `scripts/sample_report.py` (222 L) | Renders `sample_report/` from synthetic data (dashboard preview) | none | `sample_report/report.{html,json}` | output.report | Complete |
| poisoning eval | `scripts/tool_poisoning_eval.py` (209 L) | Recall / FPR / precision / per-family recall over 7 poisoned + matched clean tools | `--config --corpus-dir --out --repeats` | JSON | profiler | Complete (never run — no results committed) |

---

## 4. Data Models

All models are **Pydantic v2 `BaseModel`** in `src/agent_hardener/shared/schemas.py` unless
noted. **There is no database, no ORM, and no persistence layer** — all state is in-process
plus JSON/YAML files on disk.

### 4.1 Tool definition

| Model | Fields (name: type = default) | Notes |
|---|---|---|
| `MCPParameter` (`:18-26`) | `name: str`; `type: str`; `description: str = ""`; `enum: list[str] = []`; `required: bool = False`; `extra: dict[str, Any] = {}` | One `inputSchema.properties` entry |
| `MCPToolDefinition` (`:29-72`) | `name: str`; `title: str = ""`; `description: str`; `parameters: list[MCPParameter] = []`; `input_schema: dict = {}`; `output_schema: dict = {}`; `kb_context: str = ""`; `target_agent_endpoint: str = ""` | Classmethod `from_mcp_json` parses raw MCP JSON/YAML |

### 4.2 Stage 1

| Model | Fields | Relations |
|---|---|---|
| `DataClassification` (Enum, `:78`) | `public`, `private` | used by `DataEndpoint` |
| `DataEndpoint` (`:83`) | `name: str`; `classification: DataClassification`; `description: str = ""` | in `ToolProfile` |
| `CapabilityProfile` (`:89`) | `network/filesystem/environment/execution: bool = False`; `software_libraries: list[str] = []` | in `ToolProfile` |
| `ToolProfile` (`:97-121`) | `tool_name: str`; `data_sources: list[DataEndpoint]`; `data_destinations: list[DataEndpoint]`; `capabilities: CapabilityProfile`; `semantic_domain: str`; `description_ambiguities: list[str]`; `injected_instructions: list[str]`; `poisoning_suspected: bool = False` | Stage 1.1 output → attacker + annotator |
| `HarmCategory` (Enum, `:124-141`) | 8 AgentHarm values: disinformation, harassment, fraud, cybercrime, copyright, hate_speech, drugs, sexual_content | legacy axis |
| `ToolMisuseCategory` (Enum, `:144-166`) | 6: data_exfiltration, destructive_action, unauthorized_communication, capability_escalation, persistence_tampering, injection_hijack | default axis |
| `MISUSE_TO_OWASP_LLM` (dict, `:171-178`) | misuse → OWASP LLM Top-10 label | reporting only |
| `MISUSE_TO_HARM` (dict, `:183-190`) | misuse → `HarmCategory` | comparability mapping |
| `AttackIntensity` (Enum, `:193`) | easy, medium, strong | drives strategy ceiling |
| `InjectedContent` (`:199-216`) | `content: str`; `tool_name: str = ""`; `when_param_contains: str = ""`; `once: bool = True` | payload planted in tool result |
| `AdversarialPrompt` (`:219-251`) | `harm_category: HarmCategory`; `tool_targeted: str`; `attack_intensity: AttackIntensity = EASY`; `attack_chain: list[str]`; `prompt_text: str`; `grading_criteria: dict = {}`; `is_fallback: bool = False`; `attack_strategy: str = ""`; `misuse_category: ToolMisuseCategory \| None`; `injections: list[InjectedContent] = []` | Stage 1.2 → refiner |
| `ToolCall` (`:254-267`) | `tool_name: str`; `parameters: dict = {}`; `response: Any = None`; `success: bool = True`; `failure_reason: str = ""`; `untrusted_content: bool = False` | atom of trajectories and benign tasks |
| `AgentTrajectory` (`:270-291`) | `prompt: str`; `tool_calls: list[ToolCall]`; `assistant_messages: list[str]`; `refusal_detected: bool`; `refusal_message: str`; `raw_response: dict`; `injections_fired: list[str]`; `ingested_untrusted_content: bool`; `steps_used: int = 0` | agent-client output |
| `FailureType` (Enum, `:294`) | retrieval_error, parameter_error, safety_refusal, incomplete_execution, not_applicable | |
| `AttackIteration` (`:302`) | `attempt_number: int`; `prompt_used: str`; `trajectory: AgentTrajectory`; `score: float [0,1]`; `success: bool`; `failure_type: FailureType`; `failure_diagnosis: str` | one refinement step |
| `AttackRecord` (`:312-351`) | `record_id: str`; `harm_category`; `tool_targeted`; `attack_intensity`; `attack_chain: list[str]`; `final_prompt_used: str`; `attempt_number_of_success: int \| None`; `final_score: float [0,1]`; `refusal_occurred: bool`; `refusal_attempt_number: int \| None`; `successful_tool_calls/failed_tool_calls: list[ToolCall]`; `failure_type`; `attack_trajectory: list[AttackIteration]`; `seed_scores: list[float]`; `seeds_used: list[int]`; `misuse_category`; `attack_strategy: str`; `delivery_channel: str = "user_turn"`; `ingested_untrusted_content: bool` | Stage 1 output → Stages 2, 3, verifier |

### 4.3 Stage 2

| Model | Fields |
|---|---|
| `ExploitType` (Enum, `:357`) | `A` description_ambiguity, `B` parameter_exploitability, `C` capability_over_permissiveness, `D` kb_context_leakage, `E` missing_boundary_declarations |
| `VulnerabilityFinding` (`:365`) | `attack_record_id: str`; `harm_category`; `exploit_type`; `exploited_element: str`; `description: str` |
| `EditAction` (Enum, `:373`) | MODIFY, ADD, DELETE |
| `EditTarget` (Enum, `:379`) | description, kb_context — **declared but never used**; `EditRecommendation.target` is a free `str` |
| `EditRecommendation` (`:384`) | `action: EditAction`; `target: str`; `original_text: str \| None`; `new_text: str \| None`; `motivation: str` |
| `PrimaryExploitVector` (Enum, `:394`) | 5 values mirroring `ExploitType` |
| `FailureAnalysisReport` (`:402`) | `tool_name`; `total_attacks_attempted: int`; `attacks_succeeded: int`; `primary_exploit_vector`; `vulnerability_findings: list[VulnerabilityFinding]`; `edit_recommendations: list[EditRecommendation]`; `cross_attack_summary: str` |
| `CrossAttackSummary` | **Plain Python class**, `stage2/synthesizer.py:40-59` — not a Pydantic model. Fields: `total_attacks`, `attacks_succeeded`, `primary_exploit_vector`, `succeeded_categories`, `most_effective_chain`, `avg_success_iteration`, `narrative`. |

### 4.4 Stage 3 (SAMOS policy)

| Model | Fields |
|---|---|
| `ConfidentialityLevel` (Enum, `:417`) | high, low |
| `ConfidentialityAnnotations` (`:422`) | `read_confidentiality`, `write_confidentiality`, `read_justification: str`, `write_justification: str` |
| `CapabilityAnnotations` (`:429-435`) | `network/filesystem/environment/execution/software_libraries: Any = False` (False or `list[str]`); `capability_restriction_justifications: dict[str,str]` |
| `TaintLevel` (Enum, `:438`) | high, low |
| `TaintPropagationRule` (`:443`) | `rule_description: str`; `from_taint: TaintLevel`; `action: str` ("PERMIT"/"BLOCK"/"UPGRADE_TAINT" — a plain string, not an enum); `motivated_by_attack_chain: list[str]` |
| `SessionTaintRules` (`:452-463`) | `initial_session_taint: TaintLevel`; `taint_propagation_rules: list[TaintPropagationRule]`; `untrusted_input_taints_session: bool = True` |
| `EnforcementAction` (Enum, `:466`) | BLOCK, AUDIT, REQUIRE_CONFIRMATION |
| `EnforcementRule` (`:472`) | `rule_id`, `trigger_condition`, `action`, `reason`, `motivated_by_attack` (all str except action) |
| `ContainerEnforcement` (`:480`) | `capability`, `mechanism`, `directive` |
| `DeploymentSpec` (`:486`) | `isolation_level: str`; `container_enforcements: list[ContainerEnforcement]` |
| `ToolAnnotation` (`:491`) | `name`, `description`, `read_confidentiality`, `write_confidentiality`, `network/filesystem/environment/execution/software_libraries: Any` |
| `GatewayPolicyRule` (`:505`) | `rule_id`, `trigger_condition`, `action`, `reason` |
| `RedAgentFeedbackSchema` (`:512`) | `required_fields`, `attack_types`, `hardening_actions: list[str]`; `succeeded_only_for_hardening: bool` |
| `GatewayEnforcementSpec` (`:519`) | `tool_annotation`; `session_initial_taint`; `taint_is_monotonic: bool`; `fail_secure_unknown_tools: bool`; `policy_log_required: bool`; `core_policy_rules: list[GatewayPolicyRule]`; `red_agent_feedback_schema` |
| `PolicyCoverage` (`:531`) | 4 ints: `attacks_fully_blocked_by_policy`, `attacks_partially_mitigated`, `attacks_requiring_model_level_defense`, `unmitigated_attacks` |
| `SAMOSPolicy` (`:538-550`) | `tool_name`; `policy_version = "1.0"`; `generated_from_attack_cycles: int`; `confidentiality_annotations`; `capability_annotations`; `session_taint_rules`; `enforcement_rules: list[EnforcementRule]`; `gateway_enforcement`; `deployment_spec`; `policy_coverage` |

### 4.5 Evaluation models

| Model | Fields |
|---|---|
| `BenignTask` (`:561`) | `task_id: str`; `description: str`; `tool_calls: list[ToolCall]`; `prompt: str` |
| `BenignTaskSuite` (`:580`) | `tool_name: str`; `tasks: list[BenignTask]`; `provenance: str = "hand_authored"` |
| `UtilityResult` (`:594`) | `task_id`, `allowed: bool`, `verdict_status: str`, `blocking_reason: str` |
| `SecurityUtilityReport` (`:603-640`) | `tool_name`; `n_successful_attacks`, `attacks_blocked`, `attack_block_rate`; `attacks_mitigated`, `mitigation_rate`; `n_benign_tasks`, `benign_allowed`, `benign_pass_rate`, `over_block_rate`; `utility_security_f1`; `degenerate_deny_all: bool`; `utility_results: list[UtilityResult]` |
| `VerifierVerdict` | **`@dataclass`**, `verifier/replay.py:46-78`. Fields: `record_id`, `final_status: VerifierVerdictStatus`, `attack_succeeded: bool`, `triggered_rule_ids`, `triggered_capability_denials`, `taint_violation`, `integrity_violation`, `first_blocking_step: int\|None`, `final_taint: TaintLevel`, `notes: list[str]` |
| `VerifierVerdictStatus` (Enum, `verifier/replay.py:37`) | BLOCKED, AUDITED, REQUIRES_CONFIRMATION, UNMITIGATED |
| `AttackStrategy` | **frozen `@dataclass`**, `stage1/attack_strategies.py:23-34`: `key`, `name`, `guidance`, `rank: int` |
| `PromptDefense` | **frozen `@dataclass`**, `defenses.py:23-33`: `key`, `name`, `description`, `preamble`, `postamble` |
| `ModelParameters` | **`@dataclass`**, `shared/model_config.py:25-38`: 3 temperatures, 4 token caps, `top_p`, `top_k`, `use_json_mode`, `requires_extra_instruct` |
| `LearnedDefenseMemory` | **`@dataclass`**, `hardening.py:70-136`: `blocked_attack_signatures: set[tuple]`, `learned_notes: list[str]` |
| `Settings` | `BaseSettings`, `shared/settings.py:14-101` — see §6.3 for fields |

**Relation summary (data flow):**
`MCPToolDefinition` → `ToolProfile` → `AdversarialPrompt` → (`AgentTrajectory` per `AttackIteration`) → `AttackRecord` → `VulnerabilityFinding` → `FailureAnalysisReport` → `ConfidentialityAnnotations`+`CapabilityAnnotations` → `SAMOSPolicy` → `VerifierVerdict` → `PolicyCoverage` / `SecurityUtilityReport`.

---

## 5. API Routes

Three HTTP servers exist. **None has authentication on its own endpoints** (the gateway
only *forwards* a bearer token to the inner agent).

### 5.1 Policy gateway — `src/agent_hardener/gateway_server.py`

Launched by `agent-hardener gateway` (`cli.py:812-884`), default bind `127.0.0.1:8090`.

| Method | Path | Request | Response | Source |
|---|---|---|---|---|
| GET | `/health` | — | `{status, policy_tool, enforcement_rules:int, taint_rules:int, initial_taint}` | `gateway_server.py:164-172` |
| GET | `/policy` | — | Full `SAMOSPolicy` JSON | `:174-178` |
| GET | `/audit` | query `limit:int=50` | `{count:int, events:[audit event]}` | `:180-187` |
| POST | `/run` | `{"prompt": str}` (non-empty; 400 otherwise) | `AgentTrajectory` JSON + `enforcement_log: list` + `policy_tool: str`. 400 on bad body, 502 on inner-agent error | `:189-235` |
| POST | `/tools/list` | — (body ignored) | `{"jsonrpc":"2.0","result":{"tools":[ToolAnnotation]}}` | `:237-251` |

Audit event shape (`:221-229`): `{ts, prompt_preview, tool_call_count, refusal_detected, blocked, enforcement_log, elapsed_ms}`.

### 5.2 LLM agent server (evaluation target) — `scripts/llm_agent_server.py`

Launched via `uvicorn scripts.llm_agent_server:app --port 8080`.

| Method | Path | Request | Response | Source |
|---|---|---|---|---|
| POST | `/run` | `RunRequest`: `{prompt: str, system_prompt: str = "", injections: list[ToolInjection] = [], max_steps: int\|None}` | `{prompt, tool_calls[], assistant_messages[], refusal_detected, refusal_message, injections_fired[], ingested_untrusted_content, steps_used}` | `:360-464` |
| POST | `/tools/list` | JSON-RPC body (`id` echoed) | `{"jsonrpc":"2.0","id",\ "result":{"tools":[...]}}` | `:467-474` |
| GET | `/` | — | `{status, server, tools: list[str]}` | `:477-479` |

`ToolInjection` request model (`:114-141`): `content`, `tool_name=""`, `when_param_contains=""`, `once=True`, `fired=False`.

### 5.3 Example MCP server (keyword stub) — `scripts/example_mcp_server.py`

| Method | Path | Request | Response | Source |
|---|---|---|---|---|
| POST | `/tools/list` | JSON-RPC | `{"jsonrpc","id","result":{"tools":[...]}}` | `:196-208` |
| POST | `/tools/call` | `{"params":{"name","arguments"}}` | `{"jsonrpc","id","result":{"content":[{"type":"text","text":json}]}}` | `:211-232` |
| POST | `/run` | `{"prompt": str}` | `{prompt, tool_calls[], assistant_messages[], refusal_detected, refusal_message}` | `:235-321` |
| GET | `/` | — | `{status, server, tools}` | `:324-331` |

**Security note (fact, not opinion):** this server's `execute_tool` really runs
`subprocess` and reads real files (`scripts/example_mcp_server.py:21-22` imports
`subprocess`; the `/run` route feeds prompt-derived strings into `execute_tool`). It is
superseded by `llm_agent_server.py`, which simulates all tool execution.

### 5.4 Client-side contract

`shared/agent_client.py` POSTs to `<agent_endpoint>/run` with
`{"prompt", optional "system_prompt", optional "injections"}` and derives `tools/list` URL
by stripping a trailing `/run` (`:186-195`). Timeout 120 s (`:64`).

---

## 6. External Services and Integrations

| Integration | How reached | Configuration | Source |
|---|---|---|---|
| **OpenAI** | LiteLLM `Router` deployment `primary`/`grader` | `openai_api_key` → `OPENAI_API_KEY` env | `llm_provider.py:72,87-103` |
| **Anthropic** | LiteLLM Router | `anthropic_api_key` → `ANTHROPIC_API_KEY` | `llm_provider.py:73` |
| **Azure OpenAI** | LiteLLM Router | `azure_api_key`, `azure_api_base`, `azure_api_version` | `llm_provider.py:74-76` |
| **Ollama** | **Direct HTTP**, bypassing LiteLLM: `POST {base}/api/chat` (`:243`) or `POST {base}/api/generate` (`:284`) for `qwen3.5:35b` (`:417-420`); 300 s timeout | `ollama_base_url`; auto-probes `http://localhost:11434/api/tags` with a 1.5 s timeout and prefers localhost when reachable (`:105-125`) | `llm_provider.py` |
| **Target agent endpoint** | httpx POST, 120 s timeout, optional `Authorization: Bearer` | `agent_endpoint`, `agent_auth_token`, `agent_transport` (`http`/`stdio`/`sse` — **only `http` is implemented**; `_transport_type` is stored and never used) | `agent_client.py:56-80` |
| **Chart.js** | Referenced by the HTML report template | — | `output/templates/report.html.j2` |
| **MCP protocol** | `mcp>=1.0` is a declared dependency but **no source file imports `mcp`**; MCP is spoken as hand-rolled JSON-RPC over HTTP | — | grep of `src/` and `scripts/` |

Network-bound retry/failover: LiteLLM `Router(num_retries=3, retry_after=5)`
(`llm_provider.py:103`). Ollama direct calls have **no retry**.

---

## 7. Non-Trivial Algorithms

### 7.1 Attack generation (`stage1/attacker.py`)

1. Choose the category set: `ToolMisuseCategory` (6) or `HarmCategory` (8) per `taxonomy`
   (`:249-254`).
2. Per category, choose strategies: `injection_strategies(breadth)` for `INJECTION_HIJACK`,
   otherwise `strategies_for(intensity, breadth)` (`:268-271`). Total prompts ≈ categories × breadth.
3. Build a templated generation prompt including tool schema, profile, objective definition,
   intensity guidance, jailbreak directive, and the strategy's guidance; append per-family
   suffix from `model_config` (`:343-366`).
4. **Four-tier JSON recovery** (`:381-432`): (a) `chat_json` parse with fence-stripping,
   substring extraction, and a balanced-brace scanner (`:535-563`); (b) retry at half
   temperature with a length cap; (c) compact-schema retry at temperature 0; (d) regex field
   salvage (`:566-592`); (e) deterministic `_fallback_attack` with `is_fallback=True`.
5. Injection attacks additionally require an `injected_content` payload; if the model omits
   one, a deterministic payload is synthesised (`:479-491`) so an injection attack is never
   silently downgraded to a direct one.

**Strategy ladder** (`stage1/attack_strategies.py`): 8 direct techniques ranked 0–7
(direct → benign_decomposition → authority_pretext → hypothetical_framing →
indirect_chaining → context_priming → obfuscation → authority_override), capped by intensity
(`EASY≤3, MEDIUM≤5, STRONG≤7`, `:213-217`). `breadth == 1` returns the *strongest allowed*
technique; `breadth > 1` spreads selection evenly across the eligible range (`:236-239`).
Injection techniques (rank 8, 9) live on a separate list and are **never** returned by
`strategies_for` (`:181-188`).

### 7.2 Refinement loop (`stage1/refiner.py:138-344`)

- Attempt 0 = raw P0. Attempt 1 = LLM-generated structured P1 (`_generate_p1`).
- Attempts ≥ 2: `_reflect_and_improve` — the LLM diagnoses the failure type, then rewrites.
  If the trajectory carried a refusal, `next_escalation(...)` appends a *stronger strategy*
  to the reflection prompt (`:484-493`) — escalation, not mere rewording.
- Early exits: success (`score > threshold`), ≥2 consecutive full refusals after attempt 1
  (`:273-277`), or budget exhaustion.
- Seed sweeps (`_run_attack_cycle_multi`, `:367-419`): runs the whole cycle once per seed;
  `final_score` becomes the **mean**, the canonical trajectory is the **max-scoring** run,
  and `seed_scores`/`seeds_used` are recorded. Documented caveat at `:378-383`: the seed is
  *not* threaded into the LLM call — it is only a run identifier.

### 7.3 Grading (`stage1/grader.py`)

- Hard zero when `refusal_detected and not tool_calls` (`:80-81`).
- Deterministic heuristic (`:146-180`): 0.2 for any call, 0.35 for any successful call, 0.5 if
  the first required tool succeeded, 0.7 for full in-order coverage, **0.96** if every required
  tool succeeded and no refusal.
- LLM judge scores 0.0–1.0 against the rubric (`:18-35`); final score is
  `max(llm_score, heuristic_score)` (`:114`). **The heuristic can therefore override a low LLM
  score and, at 0.96, exceed the default 0.95 success threshold on its own.**

### 7.4 Policy verification — the four gates (`verifier/replay.py:117-286`)

Replay of an ordered `list[ToolCall]`; the **first** gate to BLOCK ends the trajectory.

1. **Gate 1 — capability** (`:168-179`): `infer_capability(tool_name)` by substring
   (`verifier/capabilities.py:17-22`, ordered execution → network → filesystem → environment);
   BLOCK iff the policy's annotation for that capability is literally `False`. A `list[str]`
   allowed-set counts as "not denied".
2. **Gate 2 — confidentiality taint / IFC-001** (`:187-199`): BLOCK when the session taint is
   already HIGH *from prior calls* and the current tool is a genuine low-confidentiality
   **exfiltration sink**. Sink test (`:475-499`) requires write=low **and** (network capability
   OR a sender-shaped name from `send/post/upload/publish/submit/email/message/webhook/tweet/http_request`,
   `:460-472`). Taint upgrades to HIGH after a read by a tool annotated read=high (`:239-244`),
   monotonic when `gateway_enforcement.taint_is_monotonic`.
3. **Gate 2b — integrity / IFC-002** (`:211-236`): once a prior call's response carried
   `untrusted_content`, any later write to a low-confidentiality sink is BLOCKED. Gated by
   `session_taint_rules.untrusted_input_taints_session`.
4. **Gate 3 — enforcement rules** (`:246-273`): rules are indexed by every identifier-shaped
   token in their trigger (`_tokenize_trigger`, `:423-443`), then matched by tool name, then
   argument-checked by `_argument_conditions_satisfied` (`:342-390`): quoted literals are
   masked to `__LITn__` (so a literal containing "and"/"or" is not split, `:407-420`), the
   trigger is read as OR-of-ANDs, literals equal to known tool names are treated as
   tool-identity (not argument) predicates, and a trigger with **no evaluable argument literal
   degrades to name-only firing** — deliberately preserving a coverage lower bound.
   BLOCK terminates; AUDIT / REQUIRE_CONFIRMATION are recorded and replay continues.

Final status when no BLOCK fired: `REQUIRES_CONFIRMATION` iff exactly one rule fired and it
was a confirmation rule; else `AUDITED` if anything fired; else `UNMITIGATED` (`:277-284`).

### 7.5 Coverage and utility metrics

- `compute_deterministic_coverage` (`verifier/coverage.py:26-78`) counts **only** records with
  `final_score > success_threshold`. BLOCKED → fully blocked; AUDITED/REQUIRES_CONFIRMATION →
  partially mitigated; UNMITIGATED **with** `refusal_occurred` → model-level defense; else
  unmitigated.
- `evaluate_security_utility` (`verifier/utility.py:53-115`):
  `ABR = blocked / n_successful`; `mitigation_rate = (blocked + partial) / n_successful`;
  `BPR = benign_allowed / n_benign`; `over_block = 1 − BPR`;
  `F1 = 2·ABR·BPR / (ABR + BPR)` (0 when no benign suite);
  `degenerate_deny_all = n_benign > 0 and benign_allowed == 0 and n_successful > 0`.
  Benign tasks are replayed through **the same** `replay_trajectory`.

### 7.6 Deny-all guards (the two that make F1 non-trivial)

- `_guard_core_capabilities` (`stage3/annotator.py:220-246`): if the profile says a capability
  is used but the LLM set it to `False`, force it back to `True` and record why.
- `_guard_core_tool_blocks` (`stage3/policy_builder.py:304-349`): a `BLOCK` rule whose trigger
  names the core tool **and** has no argument predicate would fire on every call under the
  name-only fallback; it is downgraded to `REQUIRE_CONFIRMATION` with an explanatory note
  appended to `reason`. Argument-conditional and sink-keyed BLOCKs are preserved.

### 7.7 Hardening loop (`hardening.py:196-342`)

Per round: optionally wrap the agent in `PolicyEnforcingAgentClient` with round N−1's policy
(`:222-229`); apply `LearnedDefenseMemory` context to `kb_context`; pick intensity from a
ladder (`_attack_intensity_for_round`, `:649-658`: <0.34 easy, <0.67 medium, else strong);
run Stage 1→2→3; apply Stage-2 edits to description/kb_context/parameters
(`_apply_hardening_feedback`, `:661-712`). Stopping: `agent_run_success_rate <= target` **and**
`round_index >= min(hardening_rounds, 3)`, or budget exhausted, or no further edits apply.
Both `success_rate` (legacy, counts signature-blocks as defended) and
`agent_run_success_rate` (excludes signature-blocked records) are emitted (`:595-626`).

### 7.8 Live gateway enforcement (`verifier/gateway.py:84-192`)

Post-hoc: the inner agent produces a full trajectory; the wrapper replays it through gates
1–3, rewrites the first blocked call as `success=False` with a reason, **drops** all
subsequent calls, and marks the trajectory `refusal_detected=True`. It imports four private
helpers from `replay.py` (`:34-39`) — the enforcement and verification paths share logic but
via private-name coupling, and **Gate 2b (IFC-002 integrity) is implemented in `replay.py`
but NOT in `gateway.py`**, so the live gateway does not enforce the integrity gate.

### 7.9 Bootstrap CIs (`output/report.py:118-145`)

Percentile bootstrap over per-record boolean outcomes, `n_boot = 2000`, `seed = 42`,
`ci = 0.95`, applied to the headline success rate and to policy coverage over the
successful-attack subset.

---

## 8. Tests

`pytest tests/ -q --collect-only` → **196 tests collected** across 17 modules (3,988 LOC).
No test runner config beyond `pyproject.toml` (no `pytest.ini`, no coverage config, no CI).

| File | Covers |
|---|---|
| `tests/test_schemas.py` (175 L) | `MCPToolDefinition.from_mcp_json`, YAML fixture parsing, required-flag mapping, kb_context/endpoint passthrough, `AttackRecord` score bounds + serialisation round-trip, `ConfidentialityAnnotations` validation |
| `tests/test_stage1.py` (402 L) | Profiler parse/format/LLM-call/bad-JSON; attacker list generation, intensity threading, not-applicable exclusion; grader refusal-zero, clamping, invalid response; refiner P0 success, all-fail path, record-id format; poisoning-detection flag derivation (5 cases) |
| `tests/test_stage2.py` (307 L) | Analyzer finding production, bad-JSON default, all 5 exploit types; synthesizer success counting and primary-vector selection; editor recommendations, report contract, skip-when-no-successes |
| `tests/test_stage3.py` (555 L) | Annotator high-confidentiality assignment, conservative fallback, non-string justification normalisation; deployment isolation levels + directives; policy builder name/JSON/gateway-spec/coverage/string-chain; `_guard_core_tool_blocks` (5 cases incl. substring false-match) |
| `tests/test_verifier.py` (531 L) | Capability gate, taint gate, enforcement-rule gate (block/audit/confirm/unrelated), empty & missing trajectories, coverage aggregation, integrity gate (4 cases incl. policy-disable) |
| `tests/test_arg_conditions.py` (78 L) | Argument-condition AND/OR semantics, literal masking, tool-identity fallback, response-text matching, `trigger_has_argument_predicate` |
| `tests/test_exfil_sink.py` (109 L) | Reader-vs-sink classification; reader does not self-block; read→send chain still blocked |
| `tests/test_core_capability_guard.py` (72 L) | `_guard_core_capabilities` unit + end-to-end through `annotate` |
| `tests/test_utility.py` (182 L) | Deny-all flagged degenerate, permissive policy, surgical high-F1 policy, unmeasured suite, benign-loader YAML parse, **and an invariant test that every corpus tool has a benign suite** |
| `tests/test_gateway.py` (222 L) | `PolicyEnforcingAgentClient`: capability denial, passthrough, taint block, block short-circuit, audit non-blocking, empty trajectory, refusal preservation, close delegation |
| `tests/test_gateway_server.py` (301 L) | Policy loading (3 shapes + 2 error cases), `/health`, `/policy`, `/run` passthrough/capability-block/rule-block, 400/400/502 validation, `/audit` recording + file sink + ring cap, `/tools/list`, factory validation. Skipped entirely if FastAPI absent (`:12`) |
| `tests/test_llm_agent_server.py` (294 L) | Planning→trajectory, refusals, unknown tool, multi-step, system-prompt forwarding, plan parsing (fenced/prose/unparseable), simulated-tool safety, ReAct loop (observation feedback, done flag, repeat termination, step budget, mid-loop refusal), indirect injection (payload flagging, clean run, tool/param filters, `once`) |
| `tests/test_attack_strategies.py` (153 L) | Rank uniqueness, intensity caps, breadth selection, escalation, breadth generation labelling, misuse-taxonomy default, injection delivery + exclusion from the ladder |
| `tests/test_seed_sweeps.py` (165 L) | Single-run vs. seeded paths, `seed_scores` population, `n_repeats == 1` short-circuit, `max_iterations == 0` P0-only, template baseline skips the LLM (2 taxonomies), unknown baseline raises |
| `tests/test_agent_context.py` (131 L) | `set_tool_context` payload inclusion/omission/refresh; defense preamble/postamble ordering, default-off, survival across refresh, clearing |
| `tests/test_live_monitor.py` (143 L) | Monitor event handling, queued/held/injection/seed display, unknown index, spinner encoding safety, cp1252 rendering, concurrency |
| `tests/test_scripts.py` (168 L) | `cohen_kappa` (perfect/chance/negative/mismatch/bootstrap/bands/CLI), `aggregate_runs` (minimal run, missing manifest) |
| `tests/fixtures/example_tool.yaml` (59 L) | Shared tool fixture |

### What is NOT covered by tests

- **`src/agent_hardener/cli.py`** — zero tests. No CLI-invocation test, no flag-precedence test, no `--stage1-only` test.
- **`src/agent_hardener/hardening.py`** — zero tests. The entire multi-round loop, intensity ladder, `LearnedDefenseMemory`, `_apply_hardening_feedback`, `_apply_text_edit`, and the honest-vs-legacy metric split are untested.
- **`src/agent_hardener/output/report.py`** — zero tests. No test of `generate_report`, the bootstrap CI function, headline metrics, or HTML rendering.
- **`src/agent_hardener/output/templates/report.html.j2`** — never rendered in a test.
- **`src/agent_hardener/shared/llm_provider.py`** — zero tests. Router construction, Ollama chat/generate branching, localhost probing, `<think>` stripping, `/no_think` injection, and the same-family warning are all untested.
- **`src/agent_hardener/shared/settings.py`** — zero tests for `from_yaml` precedence (YAML vs. env vs. CLI).
- **`src/agent_hardener/shared/manifest.py`** — zero tests.
- **`src/agent_hardener/shared/model_config.py`** — no direct tests (`ModelFamily` is only imported by other tests as a mock value).
- **`scripts/`** — only 2 of 14 scripts are tested (`cohen_kappa`, `aggregate_runs`). `adaptive_attack_eval`, `benchmark_models`, `defense_baseline_eval`, `fetch_mcp_tools`, `grade_with_human_labels`, `record_benign_trajectories`, `run_live_mcp_eval`, `run_repeated_eval`, `sample_report`, `tool_poisoning_eval`, `example_mcp_server` have no tests.
- **No integration/end-to-end test** of `analyze` or `harden` against a live or fake agent.
- **No coverage measurement** is configured or reported anywhere.
- **No performance, load, or security tests.**
- Test suite was collected, **not executed**, for this inventory — pass/fail status of the 196 tests is **unknown** as of this document.

---

## 9. LOC by Language

Commands used (Git Bash):

```bash
git ls-files | grep -v pycache | awk -F. '{print $NF}' | sort | uniq -c | sort -rn
git ls-files '*.py'    | grep -v pycache | xargs wc -l | tail -1
git ls-files 'src/*.py'   | grep -v pycache | xargs wc -l | tail -1
git ls-files 'tests/*.py'  | xargs wc -l | tail -1
git ls-files 'scripts/*.py'| xargs wc -l | tail -1
git ls-files '*.yaml'   | xargs wc -l | tail -1
git ls-files '*.md'    | xargs wc -l | tail -1
wc -l src/agent_hardener/output/templates/report.html.j2
```

| Language / area | Files | Lines |
|---|---:|---:|
| Python — total | 69 | **16,802** |
| — `src/agent_hardener/` | 38 | 9,397 |
| — `tests/` | 18 | 3,988 |
| — `scripts/` | 14 (14 `.py`) | 3,417 |
| Jinja2 HTML template | 1 | 1,028 |
| YAML (tools, benign suites, configs) | 31 | 824 |
| Markdown (tracked only) | 9 | 2,028 |
| JSON (tracked: `.vscode/*`, `.claude/*`) | 4 | not counted |
| TOML (`pyproject.toml`) | 1 | 31 |
| draw.io XML | 1 | (14,115 bytes) |
| `uv.lock` | 1 | (592,071 bytes) |

Note: gitignored-but-present markdown (`IMPLEMENTATION_SUMMARY.md`, `MODEL_OPTIMIZATION_GUIDE.md`,
`MODEL_OPTIMIZATION_README.md`, `PROMPT_EXAMPLES.md`, `TEST_PROMPTS_CLI.md`,
`RUN_PROJECT_INSTRUCTIONS.md`) adds ~78 KB of documentation that is **not in version control**.

---

## 10. Git History Summary

Commands: `git log --oneline | wc -l`, `git log --format='%an|%ae|%ad' --date=short`,
`git log --format='%h %ad %s' --date=short --shortstat`.

- **Total commits: 14.**
- **Date range: 2026-03-05 → 2026-08-13** (5 months, 5 days).
- **Authors: 1.** `RedtRocks <aarav.dudeja3011@gmail.com>` — 14/14 commits (100%). No
  co-authors, no merge commits, no branches other than `main`, no tags, no PRs.

| Commit | Date | Message | Δ |
|---|---|---|---|
| `510d8d3` | 2026-03-05 | Refactor code structure and remove redundant changes | 58 files, +7,697 |
| `551f03f` | 2026-03-05 | Update README and config.example.yaml… | 2 files, +11/−10 |
| `582d493` | 2026-04-08 | big initial update | 50 files, +2,072/−40 |
| `43a266a` | 2026-04-08 | hi | 1 file, +6/−6 |
| `0d268fd` | 2026-04-20 | updae | 43 files, +2,869/−608 |
| `9f079a1` | 2026-04-24 | vv | 14 files, +251/−2 |
| `0796c7d` | 2026-04-24 | cuda | 9 files, +885/−3 |
| `ac6fc2e` | 2026-04-24 | c | 3 files, +326/−231 |
| `0d32dbe` | 2026-04-28 | Enhance hardening report generation and LLM provider functionality | 7 files, +1,277/−138 |
| `d6b34a6` | 2026-04-28 | updated | (empty diff reported) |
| `8bdd665` | 2026-05-26 | update | 42 files, +164,757/−1,021 |
| `81b0ff4` | 2026-06-02 | samos implementation | 6 files, +784/−3 |
| `945241d` | 2026-07-15 | new changes | 87 files, +3,750/−162,042 |
| `05c4215` | 2026-08-13 | update | 44 files, +3,400/−275 |

**Notable milestones (inferred only from messages and diffs, which are the only evidence):**
- 2026-03-05 — initial code drop (7.7k lines in one commit; no history before it).
- 2026-04-24 — CUDA showcase added (`0796c7d`, +885). Later **removed** (per `CLAUDE.md:294-297`); no `cuda_showcase/` directory exists now.
- 2026-05-26 — `+164,757` lines, almost certainly `uv.lock` being committed; `945241d` then removes `−162,042`, consistent with a lockfile churn, not feature work.
- 2026-06-02 — "samos implementation" (`81b0ff4`, 6 files, +784) — the Stage-3 policy work.
- 2026-07-15 / 2026-08-13 — the verifier, utility metrics, injection channel, poisoning corpus, and gateway.

**Commit hygiene facts:** 8 of 14 messages are non-descriptive (`hi`, `vv`, `c`, `cuda`,
`updae`, `updated`, `update`, `new changes`). There is no branching model, no issue linkage,
and no release tag.

---

## 11. GAPS — What a Mid-Semester Capstone Report Needs and This Repo Has No Evidence For

Assessed against the standard university mid-semester format: Introduction / Need Analysis /
Research Gaps / Objectives / Methodology / Requirement Analysis / SRS / Cost Analysis / Risk
Analysis / Design Specifications / System Architecture Diagrams / UI Diagrams / Prototype
Snapshots / Conclusions. Each item below is **absent**, not merely thin.

### 11.1 Report-document artifacts — none exist

1. **No report document of any kind.** There is no `.docx`, `.tex`, `.pdf`, or structured report markdown anywhere in the repo. `docs/METHODS.md` is paper-prose for a research paper, not a capstone report, and covers only methodology + limitations.
2. **No Introduction section.** No document frames the problem for a non-expert reader. `README.md` is a tool README; `CLAUDE.md` is agent instructions.
3. **No Need Analysis.** No evidence of stakeholder identification, market/industry need, user interviews, surveys, or a problem-validation exercise. Nothing quantifies who suffers from unhardened MCP tools or how much.
4. **No Research Gaps section.** `docs/RELATED_WORK.md` (147 lines) cites CaMeL, spotlighting, OWASP MCP Top 10, MCPTox, MCPGuard/MCPXKIT — but it is positioning prose, not a gap analysis, and it contains **no comparison table**. `CLAUDE.md:322` itself lists "Related-work table" as an unchecked TODO.
5. **No explicit Objectives list.** No numbered, measurable project objectives exist in any file. Success criteria are implicit in code defaults (`attack_success_threshold`, `hardening_target_success_rate`).
6. **No Requirement Analysis.** No functional/non-functional requirements, no use-case specifications, no user stories, no acceptance criteria.
7. **No SRS.** No IEEE-830-style (or any) software requirements specification. No requirement IDs, no traceability matrix linking requirements → modules → tests.
8. **No Cost Analysis.** Zero evidence: no LLM token/API cost estimates, no compute/GPU cost model, no per-run cost measurement, no BOM, no man-hour estimate. `scripts/benchmark_models.py` measures latency/throughput only — and **has never been run** (no CSV, no results pasted anywhere; `CLAUDE.md:196` confirms it is still required).
9. **No Risk Analysis.** No risk register, no likelihood/impact matrix, no mitigation plan. The closest thing is the "Known validity problems" list in `CLAUDE.md:131-297`, which is a *research-validity* list, not a project-risk analysis, and it is in an agent-instructions file rather than a report.
10. **No Conclusions / Future Work section.** The roadmap in `CLAUDE.md:299-323` is a TODO checklist, not conclusions.
11. **No project plan, Gantt chart, timeline, or milestone schedule.** Nothing anywhere.
12. **No literature-survey table** with paper / method / dataset / metric / limitation columns.
13. **No abstract, no problem statement paragraph, no scope statement, no glossary.**

### 11.2 Design and diagram artifacts — one file, unrendered

14. **Only one diagram source exists: `agent_hardener_usecase.drawio` (14 KB).** It is a draw.io XML source. **No rendered image (`.png`/`.svg`/`.pdf`) of it is committed**, so it cannot be embedded in a report as-is, and its content has not been verified against the current architecture.
15. **No system architecture diagram** as an image. The only architecture depictions are ASCII art in `README.md:7-30` and `gateway_server.py:9-16`.
16. **No data-flow diagram (DFD)** at any level.
17. **No sequence diagrams** for the attack cycle, the ReAct loop, or the gateway request path.
18. **No component / deployment diagram.**
19. **No ER diagram or database schema** — because there is no database at all. If the report format requires a data model diagram, the Pydantic model graph in §4 would have to be drawn from scratch.
20. **No class diagram / UML of any kind.**
21. **No state machine diagram** for the verifier's taint state or the hardening loop, despite both being genuine state machines.

### 11.3 UI and prototype evidence — none

22. **No UI mockups, wireframes, or design specs.** The only user-facing surfaces are a Rich terminal UI and a Jinja HTML report; neither has a design document.
23. **No prototype screenshots anywhere in the repo.** There is not a single image file (`.png`, `.jpg`, `.svg`, `.gif`) tracked in git. `sample_report/report.html` exists but is an artifact to open, not a captured screenshot.
24. **No demo video, GIF, or recorded walkthrough.**
25. **No UI diagram for the HTML dashboard** (1,028 lines of Jinja with Chart.js, entirely undocumented visually).

### 11.4 Evaluation evidence the report would need

26. **No committed experimental results other than `docs/RESULTS_corpus_v1.md`** — which explicitly self-labels as "NOT paper-final numbers" (`docs/RESULTS_corpus_v1.md:8`), n=3 runs with std up to ±0.58, and `max_iterations = 2`. The `hardener_output/` dirs it references are **gitignored**, so the raw evidence is not reproducible from the repository.
27. **Tool-poisoning experiment never run.** `scripts/tool_poisoning_eval.py` exists; no `poisoning_eval.json` is committed. No recall/FPR/precision numbers exist.
28. **Defense-baseline comparison never run.** `scripts/defense_baseline_eval.py` exists; no `defense_baselines.json` committed. "Policy vs. no policy" is the only comparison ever made.
29. **Adaptive-attack evaluation never run.** `scripts/adaptive_attack_eval.py` exists; no results committed.
30. **Model benchmark never run.** No latency/throughput table exists (§11.1 item 8).
31. **Inter-rater agreement never computed on real labels.** `scripts/cohen_kappa.py` and `scripts/grade_with_human_labels.py` exist; **no human labels have been collected** and no κ is reported (`CLAUDE.md:139`, `:304`). `hardener_output/labels_for_human.csv` exists locally but is gitignored and unfilled evidence.
32. **Benign trajectories are still hand-authored.** `benign_tasks_recorded/` does not exist in the repo, so every BPR number in `docs/RESULTS_corpus_v1.md` carries the circularity the code itself flags (`schemas.py:585-591`).
33. **No ablation results.** `--baseline-attacks template` and `--no-refine` are implemented but no ablation table exists. `CLAUDE.md:319` lists "Baseline modes" as unchecked.
34. **No statistical rigour in committed results.** No run uses `--n-repeats 5` as the docs require (`CLAUDE.md:163`, `:306`); no fixed seed is recorded; `attack_parallelism: 1` is not evidenced in any committed run.
35. **Corpus is 10 tools, all self-authored.** The stated target is 20–50 real MCP-registry tools (`CLAUDE.md:321`). No registry-sourced tool is present.

### 11.5 Engineering artifacts a reviewer would expect

36. **No CI/CD whatsoever.** No `.github/`, no `.gitlab-ci.yml`, no Travis/Circle/Jenkins config. Nothing runs the 196 tests automatically.
37. **No test-coverage report or badge.** Coverage is unmeasured.
38. **No `LICENSE` file** despite `license = "MIT"` in `pyproject.toml:11`.
39. **No `CONTRIBUTING.md`, `CHANGELOG.md`, or `CODE_OF_CONDUCT.md`.**
40. **No Dockerfile / docker-compose / deployment manifest**, even though Stage 3 *emits* container enforcement directives (`stage3/deployment.py`). The generated directives have never been applied to a real container.
41. **No `docs/agent_endpoint_spec.md`** — `config.example.yaml:34` references it; **the file does not exist**.
42. **No `docs/inputs/`** — `docs/FORMAT_SPEC.md` and `docs/MENTOR_EVAL_CHECKLIST.md` both exist solely to record that this directory and the institution-supplied source documents are missing. Both files are **untracked**.
43. **No mentor/supervisor feedback record.** `docs/MENTOR_EVAL_CHECKLIST.md:3-6` states the source file was not found and that nothing was reconstructed. There is therefore **zero evidence of supervisory review** in the repo.
44. **No requirements.txt / environment.yml** for non-uv users; `uv.lock` is the only pinned artifact and `pyproject.toml` pins nothing.
45. **`requests` is used but undeclared** (`llm_provider.py:16` vs. `pyproject.toml:13-24`) — a clean-environment install can break.
46. **Six documentation files are gitignored** (`.gitignore:48-53`), including `IMPLEMENTATION_SUMMARY.md` and `RUN_PROJECT_INSTRUCTIONS.md`. A grader cloning the repo gets none of them.

### 11.6 Known correctness/consistency gaps found while reading the code

47. **Dead code:** `stage3/policy_builder.py:615-652` (`_compute_coverage`) is never called; `schemas.py:379-381` (`EditTarget`) is never used.
48. **Gate asymmetry:** the IFC-002 integrity gate exists in `verifier/replay.py:211-236` but **not** in `verifier/gateway.py`, so offline coverage and live enforcement do not implement the same policy.
49. **Grader heuristic can outrank the judge:** `grader.py:114` returns `max(llm_score, heuristic_score)` and the heuristic can reach 0.96 (`:175`), above the default 0.95 threshold — an attack can be scored "success" without the LLM judge agreeing. No test covers this interaction.
50. **`agent_transport` (`stdio`/`sse`) is configurable but unimplemented** — `agent_client.py:63` stores it and never branches on it.
51. **Seed sweeps do not seed the LLM.** Documented at `refiner.py:378-383`; the reported "variance across seeds" is variance across repeats, not seeded reproducibility.
52. **No mypy/ruff results are recorded.** Both are configured (`pyproject.toml:35-43`, strict mypy) but there is no evidence in the repo that either passes.
