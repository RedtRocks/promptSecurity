# Related Work

A positioning table and prose for the paper's related-work section. The goal is to
make the contribution legible against the closest prior art: **description-derived
attack-surface analysis + runtime information-flow policy synthesis for MCP-style
agent tools, evaluated with an adaptive attacker and a security/utility tradeoff.**

## Positioning table

| System / Paper | Target | Attack generation | Judged by | Defense produced | Defense *enforced*? | Utility measured? | Adaptive attacker? |
|---|---|---|---|---|---|---|---|
| **AgentDojo** (Debenedetti et al., 2024) | Tool-using agents (prompt injection) | Fixed injection task suite | Task success + attack success (deterministic checks) | — (benchmark, not a defense) | n/a | Task utility yes | Partial (attack variants) |
| **AgentHarm** (Andriushchenko et al., 2024) | Harmful agent behaviors | Curated harmful task taxonomy | Grader (rubric) | — (benchmark) | n/a | No | No |
| **InjecAgent** (Zhan et al., 2024) | Tool-integrated agents | Templated indirect prompt injections | Deterministic outcome check | — (benchmark) | n/a | No | No |
| **Agent Security Bench** (Zhang et al., 2024) | Agent stacks, multiple attack types | Broad attack battery | Mixed (rule + LLM) | Some defense baselines | Baselines only | Partial | Partial |
| **MCP-specific scans** (tool-poisoning / rug-pull writeups) | MCP tool descriptions | Manual / signature | Manual | Advisory | No | No | No |
| **This work (agent-hardener)** | MCP-style tool + live agent | LLM red-team with named, escalating techniques across 8 harm categories, iterative refinement | LLM-as-judge (cross-family) + human-κ tooling | **SAMOS IFC policy** (capability + confidentiality + taint + enforcement) | **Yes** — offline replay verifier *and* live `PolicyEnforcingAgentClient`/gateway | **Yes** — ABR/BPR/F1 with benign suites and deny-all guard | **Yes** — `scripts/adaptive_attack_eval.py` attacks the guarded agent |

## How to phrase the delta (prose)

**Versus benchmarks (AgentDojo, AgentHarm, InjecAgent, ASB).** These are
*evaluation* artifacts: fixed corpora that measure whether an agent is exploitable.
They are essential for comparability but produce no defense and, with the partial
exception of ASB, do not synthesize or enforce a per-tool policy. Our pipeline is
*generative on both sides*: it produces attacks (like a benchmark) **and** a
machine-checkable defense whose effect we then measure. Position our attack battery
as complementary to these suites — we can ingest their tasks as additional
`benign_tasks`/attack inputs, and we cite their taxonomies (AgentHarm's 8 harm
categories are ours).

**Versus MCP-specific tool-poisoning writeups.** Prior MCP security work is largely
descriptive (catalogs of tool-poisoning, rug-pull, and shadowing attacks) or
signature-based scanning. We differ by (a) treating the tool *description* as the
attack surface analyzed automatically, and (b) emitting an *enforceable* SAMOS
information-flow policy rather than an advisory.

**The two claims a reviewer will stress-test, and where we answer them.**
1. *"LLM-as-judge is circular."* → cross-family grader default, `same_family_grader`
   recorded per run, coding manual (`docs/EXPLOIT_TAXONOMY.md`), and human-κ tooling
   (`scripts/grade_with_human_labels.py`, `scripts/cohen_kappa.py`).
2. *"Coverage is gameable by a deny-all policy."* → security/utility F1 with benign
   suites and the `degenerate_deny_all` flag (`verifier/utility.py`), plus the
   `_guard_core_capabilities` guard that keeps the tool's used capabilities.
3. *"Offline replay overstates the defense."* → live enforcement
   (`PolicyEnforcingAgentClient`, `gateway_server`) and the **adaptive-attacker
   evaluation** (`scripts/adaptive_attack_eval.py`) that reruns the escalating
   attack loop against the *guarded* agent and reports absolute risk reduction with
   bootstrap CIs.

## Honest scope statement (put in Limitations, not hidden)

We analyze and constrain tool **descriptions and runtime data flows**; we do not
modify tool **implementations**. The honest framing is "description-derived
attack-surface analysis + runtime policy synthesis," not "we make the tool code
safe." Capability inference in the verifier is name-heuristic and trigger matching
is tokenized name-only (a deliberate over-approximation in the blocking direction);
see the "Known approximations" notes in `CLAUDE.md` / `verifier/`.

## Citations to resolve before submission

- Debenedetti et al. *AgentDojo: A Dynamic Environment to Evaluate Attacks and
  Defenses for LLM Agents.* NeurIPS D&B 2024.
- Andriushchenko et al. *AgentHarm: A Benchmark for Measuring Harmfulness of LLM
  Agents.* 2024.
- Zhan et al. *InjecAgent: Benchmarking Indirect Prompt Injections in
  Tool-Integrated LLM Agents.* ACL Findings 2024.
- Zhang et al. *Agent Security Bench (ASB).* 2024.
- Myers & Liskov, and the SAMOS/decentralized-label-model IFC lineage our policy
  model draws on (cite the specific DLM/DIFC papers your `SAMOSPolicy` follows).
- The MCP specification and the tool-poisoning / rug-pull advisories you reference.

> Fill in exact venues/arXiv IDs and verify author lists before camera-ready — the
> years above are approximate and must be confirmed.
