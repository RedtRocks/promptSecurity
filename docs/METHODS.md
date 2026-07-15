# Methods and Limitations (paper draft)

Draft prose for the paper's Methods and Limitations sections. Keep this in sync
with `CLAUDE.md` (the authoritative description of what the code does). Where a
claim depends on a run parameter, name it, so reviewers can reproduce.

## 1. System overview

We present an autonomous pipeline that, given only an MCP-style tool *description*
and a live agent that can call it, (i) profiles the tool's attack surface,
(ii) generates and iteratively strengthens adversarial prompts across eight harm
categories, (iii) scores exploitability with an LLM judge, and (iv) synthesizes an
enforceable information-flow (SAMOS) policy. The policy is evaluated by a
deterministic verifier and, crucially, by an **adaptive attacker** that re-runs
the escalating attack loop against the *guarded* agent.

Honest scope: the pipeline analyses and constrains tool **descriptions and runtime
data flows**; it does not modify tool **implementations**. The contribution is
"description-derived attack-surface analysis + runtime policy synthesis," not
"making the tool code safe."

## 2. Attack generation (Stage 1)

Attacks are built from named, research-grounded red-team techniques (direct,
benign-decomposition, authority pretext, hypothetical framing, indirect
tool-chaining, context priming, obfuscation, authority override), ordered by
escalation strength. Each `AdversarialPrompt` records its technique for
per-technique analysis. On refusal, the refiner escalates to a stronger technique
rather than only rewording. Ablations: `--baseline-attacks template` (no LLM
attacker) and `--no-refine` isolate the marginal value of the LLM attacker and of
iterative refinement.

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
taint rules, and enforcement rules. It is enforced by three deterministic gates
(capability, taint, enforcement), applied identically to adversarial and benign
trajectories by a single replay engine — so a benign task that gets BLOCKED is a
measurable false positive.

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
