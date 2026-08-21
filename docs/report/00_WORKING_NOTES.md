# Working Notes — Capstone Mid-Semester Report

Internal control document. **Not part of the submitted report.** Everything the
report, slides, and demo assert must be derivable from the decisions fixed here.

Project: **SecureAgent** · CPG No. **215** · Repository/package name: `agent-hardener`.

---

## 0. RELATIONSHIP BETWEEN THE APPROVED PROPOSAL AND THE CURRENT CODE

The four objectives in `docs/inputs/approved-objectives.md` were approved at Proposal
Evaluation (March 2026) and submitted at the previous evaluation. **The current codebase
is a refinement of that same system, not a different project.** Component names changed
as the architecture matured, and one component was architecturally superseded.

This has one consequence the report must handle head-on: the panel will read the
objectives in their original vocabulary and look for those components by name. The report
therefore leads with the approved wording, maps each objective to its refined
implementation (§2 below), and states plainly where the refinement **substituted** a
mechanism rather than delivering the one named. A refinement that quietly drops a named
deliverable reads as an omission; the same refinement, argued, reads as engineering
judgement. §5.1 makes the argument.

**What must never happen:** describing the deterministic information-flow gates as if
they were the Intent Alignment Layer. They are not. They serve part of the same security
goal by a different means, and the semantic goal-vs-action comparison the objective
specifies does not exist in any form.

---

## 1. THE COMPLETION FIGURE — FIXED ONCE, DERIVE EVERYTHING FROM THIS

> ## **71% weighted completion across the four panel-approved objectives.**
> ## **Of six sub-deliverables: 1 complete, 2 substantially complete, 2 partial, 1 not delivered as specified.**

Every later mention — abstract, §5.1 Work Accomplished, slide 11, slide 14, demo script,
pre-submission audit — must restate this figure and this breakdown **unchanged**.

Scored per sub-deliverable because the proposal explicitly warns:
*"O3 and O4 each bundle two deliverables… Report completion per sub-deliverable, then
roll up. Do not claim a compound objective complete on one half."*

| Obj | Sub | Deliverable (approved wording, abbreviated) | % | Evidence / gap |
|---|---|---|---:|---|
| **O1** | — | Red Agent: schema-aware adversarial attacks over data leakage, privilege escalation, unauthorized modification, **PII exposure** | **85%** | `stage1/` complete — profiler, attacker, 8 ranked techniques, refiner with escalation-on-refusal. Three of four risk categories map cleanly to `ToolMisuseCategory`. **`grep -i "pii"` across `src/` returns zero hits** — no PII-specific category, detector, or grading criterion. Refinement folded PII into `data_exfiltration` without preserving it as a distinct, reportable category. |
| **O2** | — | Defender Agent: analyse outcomes, cluster vulnerability patterns, synthesize human-readable + machine-enforceable policy in a structured format | **90%** | `stage2/analyzer.py` (5-type exploit taxonomy), `stage2/synthesizer.py` (cross-attack aggregation, primary-vector selection), `stage3/policy_builder.py` → `SAMOSPolicy` as validated JSON + HTML. **"Clusters" is classification + aggregation, not an unsupervised clustering algorithm** — describe accurately, do not use the word "clustering" unqualified. |
| **O3** | 3a | Policy Enforcement Engine with three response modes | **100%** | `EnforcementAction` = `BLOCK`, `AUDIT`, `REQUIRE_CONFIRMATION` (`schemas.py:466-469`), enforced by `verifier/replay.py` and `gateway_server.py`. **Naming deviation:** proposal says BLOCK/WARN/LOG. `AUDIT`≡LOG; `REQUIRE_CONFIRMATION` is *stronger* than WARN — human-in-the-loop rather than notify-and-continue. Present the mapping; do not silently rename either side. |
| **O3** | 3b | Policy Verification Loop confirming risk reduction by re-running known attack vectors post-policy | **60%** | Two implementations: `verifier/replay.py` (offline replay of recorded trajectories, deterministic) and `scripts/adaptive_attack_eval.py` (live re-run, unguarded vs guarded, bootstrap CIs). `hardening.py --enforce-prior-policy` closes the loop across rounds. **`adaptive_attack_eval.py` has never been executed — no risk-reduction measurement is committed anywhere.** Built, unevidenced. |
| **O4** | 4a | Intent Alignment Layer in the tool-call execution path: semantic comparison of user goal vs. AI-proposed action | **0%** | **Not delivered as specified.** No module, function, or configuration performs goal-vs-action semantic comparison. The four gates are capability-, taint-, and rule-based. The refined architecture pursues the same security goal deterministically instead of semantically — a defensible substitution that must be argued, not concealed. Largest gap against the approved proposal. |
| **O4** | 4b | Security Dashboard UI: risk scores, active policies, vulnerability history | **60%** | `output/report.py` + `templates/report.html.j2` (1,028 lines, Chart.js) renders risk scores, the active policy, findings and per-record verifier verdicts. **Static per-run artifact, not a live monitoring UI**; cross-run "vulnerability history" exists only as `scripts/aggregate_runs.py` CSV output; gateway exposes `GET /audit` as JSON with no UI. |

**Roll-ups:** O1 = 85% · O2 = 90% · O3 = (100+60)/2 = **80%** · O4 = (0+60)/2 = **30%**

**Arithmetic (equal weight per approved objective):**
`(85 + 90 + 80 + 30) / 4 = 285 / 4 = 71.25%` → **71%**

**Slide-14 chart data (sub-deliverable level, 6 bars):**
`O1 85 · O2 90 · O3a 100 · O3b 60 · O4a 0 · O4b 60`

**Status bands:** Complete ≥95% · Substantially complete 70–94% · Partial 30–69% ·
Not delivered as specified <30%.

### 1.1 Do not re-litigate

An earlier pass derived six objectives from repository evidence and scored 85%. The
panel-approved objectives are different in substance. **The 85% figure is void.** 71% is
the only figure that appears in any deliverable.

---

## 2. TERMINOLOGY MAP — APPROVED PROPOSAL vs. REFINED IMPLEMENTATION

The report must present the proposal's vocabulary first and map it to the implementation,
or the panel cannot trace objectives to code.

| Approved-proposal term | Refined implementation | Location | Relationship |
|---|---|---|---|
| Red Agent | Stage 1 — profiler, attacker, attack strategies, grader, refiner | `src/agent_hardener/stage1/` | Renamed, scope broadened |
| Defender Agent | Stage 2 (analyzer, synthesizer, editor) + Stage 3 (annotator, policy_builder) | `stage2/`, `stage3/` | Renamed, split across two stages |
| Tool usage policy (structured format) | `SAMOSPolicy` — Pydantic model serialised to JSON | `shared/schemas.py:538` | Direct, formalised |
| Policy Enforcement Engine | Four-gate deterministic replay + FastAPI gateway | `verifier/replay.py`, `gateway_server.py` | Direct |
| Response modes BLOCK / WARN / LOG | `BLOCK` / `REQUIRE_CONFIRMATION` / `AUDIT` | `shared/schemas.py:466` | Renamed; middle mode strengthened |
| Policy Verification Loop | Deterministic replay (offline) + adaptive attack eval (live) | `verifier/`, `scripts/adaptive_attack_eval.py` | Direct, but unexecuted |
| **Intent Alignment Layer** | **— none —** | — | **Superseded by deterministic IFC gates; the semantic comparison itself was not built** |
| Security Dashboard | Static HTML report (Chart.js) + gateway `/audit` JSON | `output/report.py`, `output/templates/report.html.j2` | Partial — reporting delivered, live monitoring not |
| Risk score | Attack `final_score` (0.0–1.0), policy coverage, ABR/BPR/F1 | `shared/schemas.py`, `verifier/utility.py` | Direct, formalised |

### 2.1 The O4a substitution argument (used in §5.1 and slide 5)

The Intent Alignment Layer was specified to catch the case where an agent's proposed
action diverges from the user's stated goal. The refined architecture addresses the
consequential subset of that case by different means:

- **IFC-002 (integrity gate)** blocks a consequential action once the session has ingested
  attacker-controlled content — i.e. exactly the case where the action originates from
  something other than the user's intent.
- **Argument-aware enforcement rules** discriminate malicious from benign calls on
  parameter values, not just tool identity.

**What this does not do:** compare the user's goal to the proposed action semantically.
An action fully consistent with an attacker-supplied *user turn* is not caught by either
mechanism. The substitution trades semantic coverage for determinism — the gates hold
when the model is jailbroken, whereas an LLM-based intent comparator would not. That is
the argument. It is a real trade, and §5.4 books the intent layer as remaining work
rather than declaring the trade a strict improvement.

---

## 3. TEAM — CONFIRMED FROM `docs/inputs/team.md`

Project title **SecureAgent** · CPG No. **215** · **BE Fourth Year — COE/CSE** ·
Computer Science and Engineering Department, Thapar Institute of Engineering and
Technology, Patiala.

| Name | Roll Number | Proposal-stage role |
|---|---|---|
| Aarav Dudeja | 102303179 | Overall system integration and policy enforcement |
| Akshat Srivastava | 102303904 | Red Agent — attack generation and testing |
| Hiten Yadav | 102306026 | Defender Agent — vulnerability analysis and policy generation |
| Sanil Grover | 102317215 | Red Agent — attack generation and testing |
| Simran Arora | 102306046 | Defender Agent — vulnerability analysis and policy generation |

**Mentor:** Dr. Gurpal Singh Chhabra, Assistant Professor, CSE
**Co-Mentor:** Dr. Amit Kumar Trivedi, Assistant Professor, CSE

### 3.1 Template conflicts introduced by the real team data

| # | Conflict | Handling |
|---|---|---|
| T1 | Template cover provides **four** `(<Roll Number>)NAME` lines; the team has **five** members. | Cover extended to five lines; Declaration and Acknowledgement signature tables extended from three rows to five. |
| T2 | Template cover says **"BE Third Year, CoE/CoSE"**; `team.md` says **"BE Fourth Year — COE/CSE"**. | `team.md` wins. Flagged in the audit. |
| T3 | Template Declaration boilerplate says *"during 6th semester (2024)"*; this is a Fourth Year project submitted **August 2026**. | Corrected to match actual submission. Flagged as a deliberate deviation. |

### 3.2 Still outstanding from the team (Aarav writing these himself)

| Item | Needed for | Handling |
|---|---|---|
| Contribution basis | §3.3 Work Breakdown Structure | `[VERIFY: Aarav — contribution basis]`. Proposal-stage roles used as provisional attribution, labelled as such. |
| Per-member ownership | §3.3, slide 14 per-member split | Same. **Git shows 14 commits from a single author**, so no per-member split is derivable from the repository. Must come from the team. |
| Presentation split (15 slides / 5 members) | `SLIDE_SPEC.md` presenter field | `[VERIFY: Aarav — presentation split]` on every slide. **Do not assign presenters.** |
| `mentor-eval-2.md` | `MENTOR_EVAL_CHECKLIST.md` | Confirmed unavailable by the team. Checklist stays BLOCKED; the audit reports zero addressable rows rather than claiming compliance. |

---

## 4. CHAPTER STRUCTURE — TEMPLATE OVERRIDES THE REQUESTED FILE LIST

`FORMAT_SPEC.md` §8 prescribes a **mandatory five-chapter structure**. The requested
`ch1..ch8` list is remapped onto it; no requested content was dropped.

| Requested file | Lands in |
|---|---|
| ch1_introduction | **Ch 1** Introduction (1.1–1.10) |
| ch2_literature_survey | **Ch 2** §2.1 Literature Survey (2.1.1–2.1.5) |
| ch3_analysis_design (requirements) | **Ch 2** §2.2 Software Requirement Specification |
| ch3_analysis_design (UML) | **Ch 4** §4.2 Design Level Diagrams |
| ch4_detailed_design | **Ch 3** §3.4 Tools and Technology + **Ch 4** §4.1, §4.3 |
| ch5_implementation | **Ch 4** §4.4 Snapshots of Working Prototype + **Ch 3** §3.3 WBS |
| ch6_cost_analysis | **Ch 2** §2.3 Cost Analysis |
| ch7_results_progress | **Ch 5** §5.1 Work Accomplished |
| ch8_conclusion_future | **Ch 5** §5.2 Conclusions, §5.4 Future Work Plan |

Files on disk:

```
docs/report/00_WORKING_NOTES.md         (this file — not submitted)
docs/report/front_matter.md
docs/report/ch1_introduction.md
docs/report/ch2_requirement_analysis.md
docs/report/ch3_methodology_adopted.md
docs/report/ch4_design_specifications.md
docs/report/ch5_conclusions_future_scope.md
docs/report/appendix_a_references.md
docs/report/appendix_b_plagiarism.md
```

---

## 5. NUMBERING AND CAPTION CONVENTIONS

- Captions per `FORMAT_SPEC.md` §6: `TABLE n.m:` **above** the table,
  `FIGURE n.m:` **below** the figure, ALL-CAPS label + colon.
- **Deviation, deliberate:** template shows flat numbering (`TABLE 1`); per-chapter
  numbering (`TABLE 2.3`) is used instead, as instructed.
- Every table and figure number is referenced in running text — hard template
  requirement, verbatim: *"Do refer to figure/table numbers in the running text also."*
- Citations: IEEE numeric `[n]`, in order of first appearance, space before the bracket,
  bracket before punctuation. Numbering follows `LITERATURE.md` [1]–[27].

---

## 6. EVIDENCE DISCIPLINE

- Every technical claim traces to `docs/PROJECT_FACTS.md`.
- **No result is reported as final.** `RESULTS_corpus_v1.md` self-labels as non-final
  (n=3, `max_iterations=2`, std up to ±0.58); that caveat is repeated wherever the
  numbers appear.
- Four evaluation scripts exist and have **never been run** (poisoning, defense
  baselines, adaptive attack, model benchmark). Booked as future work, never described
  as capabilities demonstrated.
- Image needs marked `[SCREENSHOT: ...]` inline, consolidated into
  `docs/SCREENSHOT_MANIFEST.md`. The repo contains **zero image files**.

---

## 7. STANDING CAVEATS THE REPORT MUST NOT CONTRADICT

1. The pipeline **never modifies a tool's implementation** — the honest framing is
   *description-derived attack-surface analysis plus runtime policy synthesis*.
2. **CaMeL [16] is not beaten on security.** The delta is the operating point.
3. Out of scope: cross-server tool shadowing, rug pulls, MCP authorization /
   confused-deputy issues.
4. Policy coverage is **measured, not proven**.
5. Tool execution in the evaluation agent is **simulated**.
6. **The Intent Alignment Layer (O4a) does not exist.** No chapter, slide, or demo step
   may imply otherwise. It is the headline item of §5.4 Future Work.
7. **"Clustering" (O2) is classification plus aggregation**, not an unsupervised
   clustering algorithm. Use accurate wording.
