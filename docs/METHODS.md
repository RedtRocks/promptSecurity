# Methods and Limitations (paper draft)

Draft prose for the paper's Methods and Limitations sections. Keep this in sync
with `CLAUDE.md` (the authoritative description of what the code does). Where a
claim depends on a run parameter, name it, so reviewers can reproduce.

## 1. System overview

We present an autonomous pipeline that, given only an MCP-style tool *description*
and a live agent that can call it, (i) profiles the tool's attack surface,
(ii) generates and iteratively strengthens adversarial prompts across six
**tool-misuse objectives**, (iii) scores exploitability with an LLM judge, and
(iv) synthesizes an enforceable information-flow (SAMOS) policy. The policy is
evaluated by a deterministic verifier and, crucially, by an **adaptive attacker**
that re-runs the escalating attack loop against the *guarded* agent.

Honest scope: the pipeline analyses and constrains tool **descriptions and runtime
data flows**; it does not modify tool **implementations**. The contribution is
"description-derived attack-surface analysis + runtime policy synthesis," not
"making the tool code safe."

## 2. Threat model

Two distinct adversaries, and the paper must not conflate them:

1. **Malicious user (direct channel).** The user asks the agent to misuse the
   tool. The instruction arrives in the user turn.
2. **Malicious content (indirect channel).** The user's request is benign; an
   attacker controls data the agent *reads* — a file, a fetched page, an email
   body, a DB row — and plants instructions there. This is indirect prompt
   injection, and it is the dominant real-world threat for tool-using agents.
3. **Malicious tool publisher (description channel).** For a third-party MCP
   server the tool *description* is attacker-supplied yet read by the agent as
   trusted text ("tool poisoning", OWASP `MCP03:2025`).

Threat 2 requires an evaluation target whose tool results re-enter its own
context. Our agent (`scripts/llm_agent_server.py`) therefore runs a **bounded
ReAct loop** — plan, act, observe, re-plan — rather than committing to a full plan
up front; a single-shot planner cannot exhibit indirect injection at all. Tool
execution stays simulated, and simulated results can carry attacker payloads
(`InjectedContent`), so no adversarial prompt ever touches a real filesystem or
network. Cross-server **tool shadowing** and **rug pulls** are out of scope.

## 3. Attack objectives and generation (Stage 1)

**Objectives.** Attacks are driven by `ToolMisuseCategory`: data exfiltration,
destructive action, unauthorized communication, capability escalation,
persistence/tampering, and injection hijack. Each names something a *tool* can be
abused for and maps to a gate the verifier enforces, and each is mapped to an OWASP
LLM Top 10 (2025) entry for reviewer legibility. AgentHarm's content-harm
categories are retained as a secondary label (`--attack-taxonomy harm` reproduces
the old behaviour) purely for comparability: "use `read_file` to produce hate
speech" is incoherent, fails for reasons unrelated to the tool's security, and
previously contributed most of the variance in our per-tool numbers.

**Techniques.** Attacks are built from named, research-grounded red-team techniques
(direct, benign-decomposition, authority pretext, hypothetical framing, indirect
tool-chaining, context priming, obfuscation, authority override), ordered by
escalation strength. On refusal, the refiner escalates to a stronger technique
rather than only rewording.

**Delivery channel.** Injection techniques (`injected_instruction`,
`injected_authority`) are a *separate axis*, never rungs on the escalation ladder —
escalating must not silently change the channel under test. For these, the attacker
emits a benign user request plus a payload planted in a tool result, and every
record carries `delivery_channel` and `ingested_untrusted_content` so direct and
indirect results are never pooled by accident.

Ablations: `--baseline-attacks template` (no LLM attacker) and `--no-refine`
isolate the marginal value of the LLM attacker and of iterative refinement.

## 3. Judging (Stage 1.3)

Exploitability is scored by an LLM-as-judge against a rubric; `attack_success_threshold
= 0.8` corresponds to "substantially achieved the harmful goal." To mitigate
self-grading we default to a **cross-family** grader (e.g. generation `gemma3`,
grading `llama3.2`), record `same_family_grader` per run, and ship a coding manual
(`docs/EXPLOIT_TAXONOMY.md`) plus human-agreement tooling
(`scripts/grade_with_human_labels.py`, Cohen's κ). *Threat to validity:* human
labels are not yet collected; κ must be reported before publication.

## 4. Policy synthesis and enforcement (Stage 3 + verifier)

The SAMOS policy carries confidentiality labels, capability annotations, session
taint rules, and enforcement rules. It is enforced by four deterministic gates
(capability, confidentiality taint, integrity taint, enforcement rules), applied
identically to adversarial and benign trajectories by a single replay engine — so a
benign task that gets BLOCKED is a measurable false positive.

**Confidentiality and integrity are duals (IFC-001 / IFC-002).** IFC-001 blocks a
write to a low-confidentiality sink once the session has read high-confidentiality
data: it stops private data flowing *out*. IFC-002 blocks a consequential action
once the session has ingested attacker-controlled tool output: it stops attacker
instructions flowing *in* and being carried out. Both test taint accumulated from
*prior* calls, never the call's own result, so neither can block a tool on its first
use. IFC-002 is declared by the policy
(`session_taint_rules.untrusted_input_taints_session`) rather than hardcoded, and
because benign trajectories carry no untrusted content it cannot over-block
legitimate use by construction — a property worth stating, since it means the
integrity gate improves ABR without any BPR cost.

**Argument-aware enforcement.** Enforcement rules are matched to a call by tool
name, then their argument-level conditions (quoted literals combined as OR-of-ANDs)
are evaluated against the call's recorded parameters and response. A rule
"block `db_query` when `query CONTAINS 'SELECT ... users'`" therefore fires only on
calls whose parameters contain that literal, not on every `db_query` call.
Tool-identity literals are distinguished from argument-value literals using the
real tool names present in the trajectory. Triggers with no evaluable argument
literal degrade to name-only firing, preserving a coverage lower-bound. The same
function runs for attack and benign trajectories, so the added precision is
symmetric and cannot selectively exempt benign calls.

**Two guards prevent degenerate deny-all policies:** `_guard_core_capabilities`
keeps any capability the profile marks as *used*; `_guard_core_tool_blocks`
downgrades only *unconditional* `BLOCK` rules keyed on the core tool (an
argument-conditional block is retained because it fires selectively).

## 5. Metrics

- **Attack block rate (ABR):** fraction of successful attacks the policy hard-BLOCKs.
- **Mitigation rate:** ABR plus attacks stopped by human-in-the-loop
  `REQUIRE_CONFIRMATION` / `AUDIT` gates. Reported *alongside* ABR, never instead:
  ABR is the un-gameable headline; mitigation rate is the fuller runtime picture.
- **Benign pass rate (BPR):** fraction of legitimate tasks still allowed.
- **Utility·security F1:** harmonic mean of ABR and BPR. A deny-all policy has
  BPR = 0 ⇒ F1 = 0, so it cannot game the headline.
- **Adaptive risk reduction:** unguarded − guarded attack-success rate when the
  attack loop runs against the deployed policy (`scripts/adaptive_attack_eval.py`),
  with bootstrap 95% CIs.
- **Defense-baseline comparison:** the same battery under prompt-level defenses
  (spotlighting, instruction defense, sandwich, prompt-level sink restriction) and
  under the enforced policy, reported as ASR / risk reduction / BPR / F1
  (`scripts/defense_baseline_eval.py`). Comparing only against *no* defense would
  overstate the contribution.
- **Tool-poisoning detection:** recall, false-positive rate on matched clean
  controls, and per-family recall (`scripts/tool_poisoning_eval.py`). The matched
  clean control is what makes this honest — a detector that flags every description
  gets perfect recall.

**Report benign-suite provenance with every BPR.** Hand-authored suites mean we
wrote both the task and its expected calls; `scripts/record_benign_trajectories.py`
captures real agent trajectories instead and marks the suite
`provenance: recorded`, which ships in `report.json`. Tasks where the agent made no
tool calls are **dropped, not kept**: they replay as "nothing to block" and would
inflate BPR with tasks that never exercised the tool.

## 6. Reproducibility

Every run writes `run_manifest.json` (models, `same_family_grader`, litellm
version, pipeline health, settings). Paper runs use `attack_parallelism = 1`, a
fixed seed, `attack_success_threshold = 0.8`, and a cross-family grader. Per-tool
error bars come from N independent runs aggregated by
`scripts/aggregate_runs.py --by-tool` (mean ± std of ABR / mitigation / BPR / F1).

## 7. Limitations (state explicitly; do not hide)

1. **Descriptions, not implementations.** See scope note above.
2. **Grader calibration.** Cross-family grading + coding manual are in place, but
   human-labeled κ is not yet collected.
2b. **No formal guarantee.** The policy is LLM-generated, so unlike CaMeL
   (arXiv:2503.18813) nothing here is provable; every claim is measured on our own
   battery, and the measurement is what we defend. See `docs/RELATED_WORK.md` for
   the delta we do and do not claim.
2c. **Simulated tool execution.** The agent's tool results are canned, so attack
   success measures whether the agent *decided* to act, not whether an OS actually
   leaked data. This is deliberate (adversarial prompts must not run real
   commands) but it means we do not observe real-world consequences.
2d. **Poisoning detection set is small.** Seven poisoned definitions with matched
   clean controls, hand-built. MCPTox (arXiv:2508.14925) covers 45+ real servers;
   ours is a proof of detection, not a benchmark, and must be described that way.
3. **Small samples / high variance.** Current results (`docs/RESULTS_corpus_v1.md`)
   are n = 2–3 with `max_iterations = 2`; per-tool F1 std reaches ±0.50. Publication
   requires n ≥ 5 with a fixed seed; the wide bars are themselves the evidence.
4. **Capability inference is name-heuristic**, and argument matching is literal-
   substring (no full expression semantics). Both are deliberate, documented
   over-approximations in the blocking direction.
5. **Policy quality varies.** The generator sometimes emits over-broad rules (e.g.
   "block any calendar event containing a URL"), which the argument-aware gate
   faithfully enforces and the BPR metric then penalises — a policy-quality signal,
   not a measurement bug. Reporting the BLOCK-vs-CONFIRMATION action distribution
   is recommended.
6. **Corpus size.** Ten tools with hand-authored benign suites; ≥20 real MCP-
   registry tools would strengthen the generalization claim.
