# Cost Inputs

Cost model for running the `agent-hardener` pipeline. Every figure is either
(a) sourced from an official pricing page with a URL, (b) converted from a
sourced USD figure at a stated FX rate, or (c) marked `[VERIFY: ...]`.
No number in this document is guessed.

**FX rate used throughout: 1 USD = ₹95.61**, spot rate as of **17 August 2026**
(see [FX note](#5-fx-note-as-of-date-and-open-verify-items)). Document prepared
18 August 2026.

---

## 1. Dependency inventory

| Service / dependency | Where used (file path) | Why needed | Priced below? |
|---|---|---|---|
| **OpenAI API** (LiteLLM `openai/*`) | `config.example.yaml:18,21`; `src/agent_hardener/shared/settings.py:23,27` — `default_model: "openai/gpt-4o"`, `openai_api_key` | Primary generation model for Stage 1 attacker/refiner/profiler and Stage 2/3 synthesis | Yes — §2.1 |
| **Anthropic API** (LiteLLM `anthropic/*`) | `config.example.yaml:9,22,85`; `src/agent_hardener/shared/settings.py:28` | Recommended **cross-family grader** to avoid self-grading (CLAUDE.md validity item 1) | Yes — §2.2 |
| **Azure OpenAI** | `config.example.yaml:15,23–25`; `src/agent_hardener/shared/settings.py:29–31`; `src/agent_hardener/shared/llm_provider.py:75` (`AZURE_API_BASE`) | Optional alternate route to GPT-4o for orgs with Azure credits | No — `[VERIFY]`, §2.3 |
| **LiteLLM** (`Router`) | `pyproject.toml:14`; `src/agent_hardener/shared/llm_provider.py:14–15,87–103` | Provider routing, retries (`num_retries=3`), failover between primary and grader deployments | Yes — free OSS library, §2.6. Note retries multiply API spend (assumption A10) |
| **Ollama (self-hosted)** → implies GPU compute | `config.example.yaml:26,98–138`; `config.run.yaml:5–7`; `src/agent_hardener/shared/llm_provider.py:81,108,117` (localhost probe at `http://localhost:11434`) | Runs `gemma3:27b` / `llama3.2` locally as generation + grader models; the actual models used in `hardener_output/run_manifest.json` | Yes — GPU compute §2.4 |
| **Cloudflare Quick Tunnel** (`cloudflared`) | `config.example.yaml:27–28` (`cloudflared tunnel --url http://localhost:11434`); `config.run.yaml:7` (`https://contracts-...trycloudflare.com`); `hardener_output/run_manifest.json` `ollama_base_url` | Exposes the GPU-hosted Ollama daemon to the machine running the pipeline | Yes — §2.5 |
| **Evaluation agent server** (FastAPI + uvicorn) | `scripts/llm_agent_server.py`; `README.md:61–62`; `pyproject.toml:27` (dev extra) | The live ReAct target agent that receives adversarial prompts. **Itself makes LLM calls** (`AGENT_LLM_MODEL`, `AGENT_MAX_STEPS=6`) — a major and easily-missed cost line | Yes — hosting §2.6, its LLM tokens §3 A4 |
| **SAMOS policy gateway** (FastAPI) | `src/agent_hardener/gateway_server.py`; `CLAUDE.md` (validity item 8) — `agent-hardener gateway --policy ... --agent-endpoint ...` | Production deployment artifact; a long-running HTTP service, so the only component with a genuinely *monthly* cost | Yes — hosting §2.6 |
| **Target agent endpoint (external)** | `config.example.yaml:34,37,41` (`agent_endpoint`, `agent_auth_token`, `agent_transport`) | Any third-party MCP agent under test; cost is the operator's, not the pipeline's | No — out of scope, third-party |
| **MCP registry fetch** | `scripts/fetch_mcp_tools.py:16,38,69` (httpx against an MCP server endpoint) | Corpus expansion (roadmap: 20–50 real MCP tools) | No — no charge identified; public endpoints |
| **Dev / test toolchain** (pytest, ruff, mypy, hatchling) | `pyproject.toml:2,27,35–43` | Local lint/type/test | Yes — free OSS, §2.6 |
| **CI** | — | **No CI config present**: no `.github/` directory exists in the repo. Runs are executed locally | No — not currently a cost |

Not present in the repo and therefore **not** priced: managed vector DBs, Serper/Tavily search APIs, Redis/Postgres, Docker registries, HuggingFace Inference. `mcp_tools/*.yaml` (`send_email`, `web_search`, `database_query`, `http_request`) describe *simulated* tools — `scripts/llm_agent_server.py` returns canned results and never contacts a real provider (CLAUDE.md validity item 10).

---

## 2. Per-provider pricing

### 2.1 OpenAI API — per 1M tokens

Source: <https://developers.openai.com/api/docs/pricing> (fetched 18 Aug 2026).
Standard (non-batch, non-fast) tier.

| Model | Input USD /1M | Output USD /1M | **Input ₹ /1M** | **Output ₹ /1M** |
|---|---|---|---|---|
| GPT-4o (repo default) | $2.50 | $10.00 | **₹239.03** | **₹956.10** |
| GPT-4o (Batch API) | $1.25 | $5.00 | **₹119.51** | **₹478.05** |
| GPT-4o mini | $0.15 | $0.60 | **₹14.34** | **₹57.37** |
| GPT-4o mini (Batch) | $0.075 | $0.30 | **₹7.17** | **₹28.68** |
| GPT-5.6-terra | $2.00 | $12.00 | **₹191.22** | **₹1,147.32** |
| GPT-5-mini | $0.25 | $2.00 | **₹23.90** | **₹191.22** |
| GPT-5-nano | $0.05 | $0.40 | **₹4.78** | **₹38.24** |

Conversion shown for one row: GPT-4o input `$2.50 × 95.61 = ₹239.03 per 1M tokens`.

Batch pricing is a real option here — Stage 1 attack generation and Stage 2
analysis are not latency-sensitive — but the current code path is synchronous
(`llm.chat_json`, `src/agent_hardener/shared/llm_provider.py:142`), so scenarios
below use **standard** rates.

### 2.2 Anthropic (Claude) API — per 1M tokens

Source: <https://platform.claude.com/docs/en/about-claude/pricing> (fetched 18 Aug 2026).
Base input / output, global inference geography.

| Model | Input USD /1M | Output USD /1M | **Input ₹ /1M** | **Output ₹ /1M** |
|---|---|---|---|---|
| Claude Haiku 4.5 | $1.00 | $5.00 | **₹95.61** | **₹478.05** |
| Claude Sonnet 5 | $2.00 | $10.00 | **₹191.22** | **₹956.10** |
| Claude Sonnet 4.6 | $3.00 | $15.00 | **₹286.83** | **₹1,434.15** |
| Claude Opus 5 | $5.00 | $25.00 | **₹478.05** | **₹2,390.25** |
| Claude Haiku 4.5 (Batch) | $0.50 | $2.50 | **₹47.81** | **₹239.03** |
| Cache read (hit) | 0.1× base input | — | 0.1× base input | — |

Note: `config.example.yaml:9,85` still names `anthropic/claude-3-5-sonnet-20241022`,
which is retired on the first-party API. Any paper run must repin to a live
revision string (CLAUDE.md validity item 4). **Claude Haiku 4.5 is the cheapest
credible cross-family grader** and is what §4 scenarios B and C use.

### 2.3 Azure OpenAI Service

`[VERIFY: Microsoft Azure, Azure OpenAI Service — GPT-4o / GPT-4o mini global-standard per-1M-token rates]`
The official pricing page (<https://azure.microsoft.com/en-us/pricing/details/cognitive-services/openai-service/>)
rendered all model rates as `$-` placeholders when fetched on 18 Aug 2026, and
Microsoft's own note says prices vary by agreement and currency. No figure is
recorded here rather than assume parity with first-party OpenAI. Azure is an
optional route (`config.example.yaml:15`), so this gap does not block §4.

### 2.4 GPU compute for self-hosted Ollama — per hour

Source: <https://www.runpod.io/pricing> (fetched 18 Aug 2026). Per-second billing available.

| GPU | Tier | USD /hr | **₹ /hr** |
|---|---|---|---|
| RTX A6000 48GB | Community | $0.33 | **₹31.55** |
| RTX A6000 48GB | Secure | $0.53 | **₹50.67** |
| RTX 4090 | Community | $0.34 | **₹32.51** |
| RTX 4090 | Secure | $0.74 | **₹70.75** |
| L40S | Community | $0.79 | **₹75.53** |
| L40S | Secure | $0.99 | **₹94.65** |
| A100 80GB PCIe | Community | $1.19 | **₹113.78** |
| A100 80GB PCIe | Secure | $1.39 | **₹132.90** |
| A100 80GB SXM | Community | $1.39 | **₹132.90** |
| H100 80GB PCIe | Community | $1.99 | **₹190.26** |
| H100 80GB PCIe | Secure | $2.89 | **₹276.31** |
| H100 80GB SXM | Secure | $3.29 | **₹314.56** |

Conversion shown: A100 80GB PCIe community `$1.19 × 95.61 = ₹113.78/hr`.

**Sizing note (assumption, not a source):** the run in
`hardener_output/run_manifest.json` used `ollama/gemma3:27b` + `ollama/llama3.2:latest`
concurrently. A 27B model at Q4 needs roughly 18–20 GB of VRAM, so a single
48GB A6000 or L40S holds both resident. A100/H100 rows are listed for headroom
only; scenarios below price the A6000/A100 tiers.

**Owned/university GPU** carries no rental line, only electricity — see A7/A8 in §3.

### 2.5 Cloudflare Tunnel

Sources: <https://www.cloudflare.com/plans/zero-trust-services/>,
<https://en-us.www.cloudflare.com/teams-pricing/>.

| Item | USD | **₹** |
|---|---|---|
| Cloudflare Quick Tunnel (`cloudflared tunnel --url ...`, `*.trycloudflare.com`) | $0 | **₹0** |
| Cloudflare Zero Trust — Free plan (up to 50 users) | $0 | **₹0** |
| Cloudflare Zero Trust — Standard, per user / month | $7 | **₹669.27** |

The repo uses the **Quick Tunnel** form exactly (`config.example.yaml:27`,
`config.run.yaml:7`), which is unauthenticated, ephemeral, and free. Cost is ₹0
for the research workload. A production gateway would want a named tunnel behind
Zero Trust Access; at a 1–5 person capstone team that still sits inside the free
50-user tier, so ₹0 either way.

`[VERIFY: Cloudflare, Zero Trust Standard $7/user/month]` — the $7 figure comes
from Cloudflare's plans/teams-pricing pages via search snippets; the fetched
landing page itself showed no numeric table. Not load-bearing (unused in §4).

### 2.6 Hosting and other fixed costs — per month

| Item | USD /mo | **₹ /mo** | Source |
|---|---|---|---|
| Render Web Service — Free tier (spins down when idle) | $0 | **₹0** | third-party, see VERIFY below |
| Render Web Service — Starter (0.5 CPU, 512 MB) | $7 | **₹669.27** | third-party, see VERIFY below |
| Render Web Service — Standard (1 CPU, 2 GB) | $25 | **₹2,390.25** | third-party, see VERIFY below |
| Local workstation hosting for `llm_agent_server` / gateway during research | $0 | **₹0** | `README.md:61–62` — run via `uvicorn` on localhost |
| Ollama runtime | $0 | **₹0** | open source (`config.example.yaml:26`) |
| LiteLLM, FastAPI, uvicorn, pytest, ruff, mypy, hatchling | $0 | **₹0** | `pyproject.toml:13–27` — all OSS |
| CI minutes | $0 | **₹0** | no `.github/` in repo; nothing to bill |

`[VERIFY: Render, Web Service Starter and Standard monthly price]` — the $7 /
$25 figures are from third-party pricing aggregators
(<https://www.srvrlss.io/provider/render/>, <https://kuberns.com/blogs/render-pricing/>),
because <https://render.com/pricing> returned only navigation chrome when fetched.
Render also charges a separate workspace fee on some plans that is **not**
included above.

Scenarios below use **Render Starter (₹669.27/mo)** as the placeholder for
hosting the SAMOS gateway, and ₹0 for the research-time agent server (it runs on
the researcher's own machine per `README.md`).

---

## 3. Assumptions register

Every item below is an **assumption**, not a measured fact. Where the repo
constrains the value, the constraining file is cited — the *derived* number is
still an assumption.

| # | Assumption | Basis / constraint in repo |
|---|---|---|
| **A1** | One "pipeline run" = `analyze` on **one** tool with the default `misuse` taxonomy: **6 attack categories × attack_breadth 1 = 6 adversarial prompts**. | `CLAUDE.md` (six `ToolMisuseCategory` values); `config.example.yaml:73` `attack_breadth: 1` |
| **A2** | `max_iterations = 6` refinement iterations per attack, and attacks run to the budget (worst case) rather than terminating early. | `config.example.yaml:44` |
| **A3** | **Pipeline LLM calls per run ≈ 84**: 1 profile + 6 attack-generation + (6 grade + 5 refine) × 6 attacks = 66 + Stage 2 (6 analyze + 1 synthesize + 1 editor) + Stage 3 (1 annotate + 2 policy-build) = 84. | Call sites counted in `stage1/{profiler,attacker,refiner,grader}.py`, `stage2/{analyzer,synthesizer,editor}.py`, `stage3/{annotator,policy_builder}.py` |
| **A4** | **Target-agent LLM calls per run ≈ 108**: 6 attacks × 6 iterations × **3 ReAct steps average** (budget is 6, `AGENT_MAX_STEPS`). This is a genuine cost line, not overhead — the agent under test is itself an LLM. | `scripts/llm_agent_server.py`; `README.md:61` |
| **A5** | Token shape per **pipeline** call: **2,000 input / 600 output**. Output anchored to the configured caps (`max_tokens_attack 1500`, `max_tokens_grade 600–800`, `max_tokens_profile 1000–1200`) assuming responses land well under cap; input assumed from tool schema + prompt + trajectory context. Grader calls assumed 2,000 in / 400 out. | `src/agent_hardener/shared/model_config.py:31–34,48–108` |
| **A6** | Token shape per **agent** call: **1,500 input / 250 output** (system prompt + 10 tool schemas + growing ReAct history). | Assumption; `mcp_tools/` holds 10 tools, all auto-loaded |
| **A7** | Wall clock **25 minutes per run** at `max_iterations: 6`. Extrapolated from the recorded 269.93 s for a `read_file` run at `max_iterations: 2` with 8 prompts, scaled ~3× for iteration budget and ~1.5× for slack. | `hardener_output/run_manifest.json` (`elapsed_seconds: 269.93`) |
| **A8** | GPU node draws **0.7 kW average** under sustained inference (card + host). | Assumption; no power telemetry in repo |
| **A9** | Electricity at **₹8.00 / kWh**. Indian domestic average is quoted at ~₹5.5/unit and commercial rates above ₹10–14/unit; ₹8 is a mid-point for an institutional connection. Source for the range: <https://kimbal.io/blog/how-much-does-1-unit-of-electricity-cost-in-india/> | Assumption on top of a sourced range |
| **A10** | **+20% API token overhead** for retries and failed JSON parses. LiteLLM `Router` is configured with `num_retries=3`, and `attacker.py` / `profiler.py` both have explicit retry + compact-retry fallback paths that re-issue calls. | `src/agent_hardener/shared/llm_provider.py:103`; `stage1/attacker.py:389,410`; `stage1/profiler.py:132` |
| **A11** | **Paper protocol = 50 runs**: 10 corpus tools × 5 independent repeats (the ≥5× requirement in CLAUDE.md's roadmap). Ablations (`--baseline-attacks template`, `--no-refine`) and `defense_baseline_eval.py` are **excluded** and would add roughly another 50–100% on top. | `CLAUDE.md` roadmap; `mcp_tools/` (10 tools) |
| **A12** | Gateway hosted for **1 month** for the demo/eval window, not continuously. | Assumption |
| **A13** | Prompt caching and Batch API are **not** used (the code path is synchronous and uncached), so no discount is applied. Enabling batch would roughly halve the §4-B API line. | `src/agent_hardener/shared/llm_provider.py:142` |

### Derived per-run token volume (from A1–A6, before A10 overhead)

| Component | Calls | Input tokens | Output tokens |
|---|---|---|---|
| Generation (profile, attack, refine, Stage 2, Stage 3) | 48 | 48 × 2,000 = **96,000** | 48 × 600 = **28,800** |
| Grading (6 iterations × 6 attacks) | 36 | 36 × 2,000 = **72,000** | 36 × 400 = **14,400** |
| Target agent (ReAct) | 108 | 108 × 1,500 = **162,000** | 108 × 250 = **27,000** |
| **Per run total** | **192** | **330,000 (0.33 M)** | **70,200 (0.0702 M)** |
| **× 50 runs (A11)** | 9,600 | **16.50 M** | **3.51 M** |

---

## 4. Scenario cost estimates

All three scenarios cover the **same workload**: 50 pipeline runs (A11) plus one
month of gateway hosting (A12).

### Scenario A — All-local Ollama on an owned / university GPU

No API spend; the only cash cost is electricity.

```
GPU-hours       = 50 runs × 25 min (A7) / 60          = 20.83 h
Energy          = 20.83 h × 0.7 kW (A8)               = 14.58 kWh
Electricity     = 14.58 kWh × ₹8.00 (A9)              = ₹116.67
Ollama runtime                                         = ₹0        (OSS)
Cloudflare Quick Tunnel                                = ₹0        (§2.5)
Agent server + gateway on local machine (research)     = ₹0        (README.md:61)
Gateway hosting, Render Starter × 1 month (A12)        = ₹669.27   [VERIFY: Render]
-------------------------------------------------------------------
TOTAL                                                  ≈ ₹786
```

**Marginal cost excluding hosting: ≈ ₹117.** If the gateway also runs on the
owned machine (entirely reasonable for a capstone demo), the total is **≈ ₹117**.

*Opportunity-cost view, if that GPU had to be rented instead:*
`20.83 h × ₹113.78/hr (A100 80GB PCIe community) = ₹2,370` — i.e. the owned GPU
is worth about ₹2,400 of avoided rental for this workload. On an A6000 community
instance it would be `20.83 × ₹31.55 = ₹657`.

### Scenario B — Hosted API only

Generation on GPT-4o, grading on Claude Haiku 4.5 (cross-family, satisfying the
self-grading constraint), target agent on GPT-4o mini.

Per-run, using the §3 derived volumes:

```
Generation  (GPT-4o, §2.1)
  input   0.096 M × ₹239.03   = ₹22.95
  output  0.0288 M × ₹956.10  = ₹27.54
                              -> ₹50.49

Grading     (Claude Haiku 4.5, §2.2)
  input   0.072 M × ₹95.61    = ₹6.88
  output  0.0144 M × ₹478.05  = ₹6.88
                              -> ₹13.76

Target agent (GPT-4o mini, §2.1)
  input   0.162 M × ₹14.34    = ₹2.32
  output  0.027 M × ₹57.37    = ₹1.55
                              -> ₹3.87

Per-run subtotal              = ₹68.12
```

```
50 runs (A11)                 = 50 × ₹68.12          = ₹3,406.00
Retry overhead +20% (A10)     = ₹3,406 × 0.20        = ₹681.20
API total                                            = ₹4,087.20
Gateway hosting, Render Starter × 1 month (A12)      = ₹669.27   [VERIFY: Render]
Cloudflare Tunnel (not needed — no local Ollama)     = ₹0
GPU compute                                          = ₹0
-------------------------------------------------------------------
TOTAL                                                ≈ ₹4,756
```

**Sensitivity — the agent model dominates the call count, the generation model
dominates the rupees.** Swapping generation GPT-4o → GPT-4o mini drops the
per-run generation line from ₹50.49 to `0.096 × 14.34 + 0.0288 × 57.37 = ₹3.03`,
taking the 50-run API total to about `50 × (3.03 + 13.76 + 3.87) × 1.2 = ₹1,240`.
Conversely, running generation on Claude Opus 5 would put the generation line at
`0.096 × 478.05 + 0.0288 × 2390.25 = ₹114.7/run` → ~₹7,960 for the API line alone.
Enabling the Batch API (A13) roughly halves whichever figure applies.

### Scenario C — Hybrid: local Ollama + hosted independent grader

This is the configuration the research-validity constraints actually push toward:
generation and the target agent stay on the owned GPU (cheap, reproducible,
no rate limits), while **grading** moves to a hosted cross-family model so the
pipeline is not grading itself.

```
Local side (as Scenario A)
  GPU-hours    = 20.83 h ; energy 14.58 kWh × ₹8.00  = ₹116.67
  Ollama + Cloudflare Quick Tunnel                   = ₹0

Hosted grader (Claude Haiku 4.5, §2.2)
  per run: 0.072 M × ₹95.61 + 0.0144 M × ₹478.05     = ₹13.76
  50 runs: 50 × ₹13.76                               = ₹688.00
  retry overhead +20% (A10): ₹688 × 0.20             = ₹137.60
  grader total                                       = ₹825.60

Gateway hosting, Render Starter × 1 month (A12)      = ₹669.27   [VERIFY: Render]
-------------------------------------------------------------------
TOTAL                                                ≈ ₹1,612
```

*Variant — hybrid with a **rented** GPU instead of an owned one*
(A100 80GB PCIe community, §2.4):

```
GPU rental   20.83 h × ₹113.78/hr                    = ₹2,370.00
Hosted grader                                        = ₹825.60
Gateway hosting                                      = ₹669.27
(no electricity line — included in rental)
-------------------------------------------------------------------
TOTAL                                                ≈ ₹3,865
```

### Summary

| Scenario | Total (₹) | Total (USD @ 95.61) | Dominant cost |
|---|---:|---:|---|
| **A — All-local, owned GPU** | **₹786** | $8.22 | Gateway hosting; electricity is ₹117 |
| **B — Hosted API only** | **₹4,756** | $49.74 | GPT-4o generation tokens (₹2,525 of the API line) |
| **C — Hybrid (local + hosted grader)** | **₹1,612** | $16.86 | Hosted grader + gateway hosting |
| *C-variant — Hybrid, rented GPU* | *₹3,865* | *$40.42* | *GPU rental* |

Scenario C is the recommended configuration: it costs about a third of B while
removing the self-grading validity objection that A (all-local, likely
same-family grader) cannot remove on its own without a second local family —
which `config.run.yaml` does in fact do (`gemma3:27b` + `llama3.2`), making A
defensible at near-zero cost, just with two local models rather than an
independent hosted judge.

---

## 5. FX note, as-of date, and open `[VERIFY]` items

**FX.** All INR figures are USD source figures × **95.61**. That is the USD/INR
spot rate for **17 August 2026** (1 USD = 95.61 INR), per
<https://www.exchangerates.org.uk/USD-INR-spot-exchange-rates-history-2026.html>,
consistent with the Federal Reserve H.10 release of 17 Aug 2026
(<https://www.federalreserve.gov/releases/h10/hist/dat00_in.htm>). The rate
traded between 95.2969 (12 Aug) and 95.7338 (17 Aug) that week, so a ±0.5%
band on every INR figure here is appropriate. Providers bill in **USD**; the
INR figures are indicative and will move with the rate and with any card
forex markup (typically 2–3.5%, **not** included above).

**Pricing as-of date:** all provider pages fetched **18 August 2026**.
Re-verify before quoting in the paper — LLM list prices have changed repeatedly
within single quarters (the Claude Sonnet 5 introductory-price note on
Anthropic's own page is a live example).

**Still open — `[VERIFY]` items (4):**

1. `[VERIFY: Microsoft Azure, Azure OpenAI Service — GPT-4o / GPT-4o mini per-1M-token rates]` — official page served `$-` placeholders. §2.3. *Not load-bearing; Azure is unused in §4.*
2. `[VERIFY: Render, Web Service Starter plan monthly price]` — $7/mo taken from third-party aggregators; official page unfetchable. §2.6. *Load-bearing: appears in all three scenarios.*
3. `[VERIFY: Render, Web Service Standard plan monthly price and any separate workspace fee]` — $25/mo, same provenance problem; a workspace fee may apply on top. §2.6.
4. `[VERIFY: Cloudflare, Zero Trust Standard $7/user/month]` — from search snippets of Cloudflare's own pages, not from a fetched numeric table. §2.5. *Not load-bearing; the repo uses free Quick Tunnels and any realistic team size fits the free 50-user tier.*

**Not verifiable from pricing pages at all** (they are assumptions, listed in §3,
and should be replaced with measurements before publication): A5/A6 token shapes,
A3/A4 call counts, A7 wall-clock, A8 GPU power draw, A10 retry overhead. The
cleanest fix for A3–A6 is to log LiteLLM's `usage` object per call and emit token
totals into `run_manifest.json` alongside the existing `pipeline_health` block —
at which point scenarios B and C become measured rather than modelled.
