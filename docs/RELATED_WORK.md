# Related Work

Positioning for the paper. The contribution to defend is: **automated,
description-derived attack-surface analysis for MCP-style tools that synthesises a
runtime information-flow policy, evaluated against both direct misuse and indirect
prompt injection with an explicit security/utility tradeoff.**

Citations below were verified against arXiv/OWASP in July 2026. Author lists and
IDs are confirmed; **check page numbers and final venues before camera-ready.**

## The closest prior art — read this before claiming novelty

**CaMeL — "Defeating Prompt Injections by Design"** (Debenedetti, Shumailov et al.,
Google DeepMind, [arXiv:2503.18813](https://arxiv.org/abs/2503.18813), Mar 2025).
This is the paper the work must be differentiated from, and the omission of it from
an earlier draft was the single biggest citation gap. CaMeL extracts control and
data flow from the *trusted* query so untrusted data can never influence program
flow, and uses **capabilities to prevent exfiltration over unauthorised data
flows, enforced when tools are called**. It reports 77% of AgentDojo tasks solved
with provable security vs. 84% undefended — i.e. it already frames results as a
security/utility tradeoff, which is also our headline framing.

Honest delta, stated as narrowly as it should be:

| | CaMeL | This work |
|---|---|---|
| Policy origin | Hand-specified/derived from a trusted program the interpreter builds | **Synthesised automatically from the tool description** by an LLM pipeline |
| What it needs | A rewritten agent architecture (custom interpreter, P-LLM/Q-LLM split) | Wraps an **existing** agent at the dispatch boundary; no agent rewrite |
| Guarantee | Strong, by construction, for the flows it models | Weaker: measured, not proven — the policy is LLM-generated and may be wrong or over-broad |
| Attack side | Uses AgentDojo's fixed suite | **Generates** attacks per tool, escalating on refusal |
| Tool-poisoning | Out of scope (query is trusted) | Detection measured directly (the description is our input) |

Do **not** claim we beat CaMeL on security. The claim is that we cover a different
operating point: no architectural change, policy obtained automatically for a tool
you did not write, and the *description* itself treated as untrusted. CaMeL is the
stronger guarantee where you can afford to rebuild the agent.

**Design Patterns for Securing LLM Agents against Prompt Injections**
(Beurer-Kellner et al., [arXiv:2506.08837](https://arxiv.org/abs/2506.08837), Jun
2025). Six principled patterns with provable injection resistance, applied to ten
case studies, explicitly analysed for the utility/security trade-off. Their core
finding — that security comes from *constraining what the agent may do* rather than
from better prompting — is the design argument our enforcement gates instantiate.
Position our policy synthesis as an automated way to land on one of these patterns
per tool.

## Benchmarks (evaluation artifacts, not defenses)

| System | Target | Attacks | Judged by | Defense produced? | Utility measured? |
|---|---|---|---|---|---|
| **AgentDojo** (Debenedetti et al., NeurIPS D&B 2024) | Tool-using agents | Fixed injection suite | Deterministic checks | No | Yes |
| **AgentHarm** (Andriushchenko et al., ICLR 2025) | Harmful agent behaviour | Curated harmful tasks | Rubric grader | No | No |
| **InjecAgent** (Zhan et al., ACL Findings 2024) | Tool-integrated agents | Templated indirect injections | Deterministic check | No | No |
| **MCPTox** ([arXiv:2508.14925](https://arxiv.org/pdf/2508.14925)) | **Real MCP servers** | Tool-poisoning battery | Outcome check | No | Partial |
| **This work** | MCP tool + live agent | **Generated**, escalating, direct *and* injected | LLM judge (cross-family) + κ tooling | **Yes**, enforced | **Yes** (ABR/BPR/F1) |

Two notes that must go in the text, not be quietly omitted:

- **We take AgentHarm's taxonomy but no longer lead with it.** Content-harm
  categories (`hate_speech`, `drugs`, …) do not describe what a *tool* can be
  abused for; our primary axis is now `ToolMisuseCategory` (exfiltration,
  destructive action, capability escalation, injection hijack, …), each mapping to
  a gate the verifier enforces. AgentHarm labels are retained as a secondary field
  purely for comparability.
- **MCPTox is a direct competitor for the poisoning result** and reports attack
  success >60% across 45+ real MCP servers. Our poisoning experiment is a
  *detection* task on a small hand-built matched-control set — much weaker
  evidence. Either cite MCPTox as the attack-side reference and frame ours as
  "can the analysis pipeline notice it", or scale up. Do not present a 7-positive
  set as a benchmark.

## Prompt-level defenses (our baselines)

**Spotlighting / datamarking** (Hines, Lopez, Hall, Zarfati, Zunger, Kiciman;
Microsoft; [arXiv:2403.14720](https://arxiv.org/abs/2403.14720), Mar 2024). Signals
input provenance so the model can separate data from instructions; reports attack
success dropping from >50% to <2% on GPT-family models with minimal task-efficacy
loss. Implemented as a baseline condition in `agent_hardener/defenses.py`.

**Those numbers set a high bar for our comparison.** If our policy does not clearly
beat spotlighting on the ABR/BPR frontier in `scripts/defense_baseline_eval.py`,
the honest conclusion is that the policy's value is *enforcement independent of
model compliance* (it holds when the model is jailbroken), not a higher block rate.
Say that rather than burying the baseline.

## MCP-specific security

- **OWASP MCP Top 10 (2025)** — `MCP03:2025 Tool Poisoning`
  ([owasp.org](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning)).
  Cite this for the threat-model framing; our `ToolMisuseCategory` entries are
  mapped to OWASP LLM Top 10 entries in `shared/schemas.py`.
- **Invariant Labs (Apr 2025)** — first public tool-poisoning PoC, plus **tool
  shadowing** (a malicious server overriding a trusted tool) and **MCP rug pulls**
  (a benign tool updated with harmful logic after approval). Shadowing and rug
  pulls are **not** covered by our work; list them as scope limits.
- **Simon Willison's MCP prompt-injection analysis**
  ([simonwillison.net](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)) —
  useful for the "descriptions are trusted text supplied by third parties" framing.
- **NSA/CISA MCP security guidance** (Jun 2026,
  [media.defense.gov](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF))
  — cite for practitioner relevance of the deployment/gateway story.
- **MCPGuard** ([arXiv:2510.23673](https://arxiv.org/pdf/2510.23673)) and
  **MCPXKIT** ([arXiv:2508.12538](https://arxiv.org/pdf/2508.12538)) — automated
  MCP server vulnerability detection. Closest work to our poisoning detector;
  check whether either already does description-level detection before claiming it
  as a contribution.

## The four objections a reviewer will raise, and where we answer them

1. *"LLM-as-judge is circular."* → cross-family grader by default,
   `same_family_grader` recorded per run, coding manual
   (`docs/EXPLOIT_TAXONOMY.md`), κ tooling (`scripts/grade_with_human_labels.py`).
   **Still open: no human labels collected yet.**
2. *"Coverage is gameable by deny-all."* → security/utility F1 with benign suites,
   `degenerate_deny_all` flag, and the two policy guards (`verifier/utility.py`,
   `stage3/policy_builder.py`).
3. *"You wrote both the benign tasks and their expected calls."* →
   `scripts/record_benign_trajectories.py` captures benign trajectories from a live
   agent and marks the suite `provenance: recorded`; the provenance ships in
   `report.json`. **Still open: recorded suites not yet generated for the corpus.**
4. *"A system-prompt line would do the same."* →
   `scripts/defense_baseline_eval.py` runs spotlighting / instruction-defense /
   sandwich / sink-restriction under identical conditions. **Still open: not yet
   run.**

## Scope limits to state explicitly

We analyse and constrain tool **descriptions and runtime data flows**; we do not
modify tool **implementations**. Capability inference is name-heuristic and
argument matching is literal-substring — both deliberate over-approximations in the
blocking direction. Cross-server **tool shadowing**, **rug pulls**, and MCP
**authorization/confused-deputy** issues are out of scope. The policy is
LLM-generated, so unlike CaMeL it carries **no formal guarantee**; every number is
measured, and the measurement (not the mechanism) is what we defend.

## Citations to finalise

- Debenedetti et al. *Defeating Prompt Injections by Design.* arXiv:2503.18813, 2025. ✅ verified
- Beurer-Kellner et al. *Design Patterns for Securing LLM Agents against Prompt Injections.* arXiv:2506.08837, 2025. ✅ verified
- Hines et al. *Defending Against Indirect Prompt Injection Attacks With Spotlighting.* arXiv:2403.14720, 2024. ✅ verified
- OWASP. *MCP Top 10 (2025)* — MCP03 Tool Poisoning. ✅ verified
- *MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers.* arXiv:2508.14925. ⚠️ confirm author list
- Debenedetti et al. *AgentDojo.* NeurIPS D&B 2024. ⚠️ confirm exact venue string
- Andriushchenko et al. *AgentHarm.* ⚠️ confirm ICLR 2025 vs arXiv-only
- Zhan et al. *InjecAgent.* ACL Findings 2024. ⚠️ confirm page range
- Myers & Liskov, DLM/DIFC lineage for the SAMOS label model. ⚠️ pick the specific papers our policy model follows
- The MCP specification (version the agent targets). ⚠️ pin the spec revision
