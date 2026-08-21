# Pre-Submission Audit — SecureAgent Mid-Semester Report

Written adversarially, on the assumption that **the panel has read the code**. Findings are
stated as defects, not as reassurance. Items marked **BLOCKER** must be resolved before
submission; **RISK** items will survive submission but will be asked about.

Audit date: 19 August 2026. Checks marked *(automated)* were executed against the source
files, not asserted.

---

## 1. Executive summary

| Category | Result |
|---|---|
| Mentor checklist rows addressed | **0 of 0** — source file does not exist (BLOCKER) |
| Approved objectives discussed and status claimed | 4 of 4 ✓ |
| References cited in text and in bibliography | 27 of 27 ✓ *(automated)* |
| Figures captioned, numbered, referenced in body | 16 of 16 ✓ *(automated)* |
| Tables captioned, numbered, referenced in body | 24 of 24 ✓ *(automated)* |
| Outstanding `[SCREENSHOT:]` markers | 10 in submitted files (BLOCKER) |
| Outstanding `[VERIFY:]` markers | 9 in submitted report files |
| Completion figure consistent across artifacts | ✓ 71% everywhere *(automated)* |
| Claims the code does not support | **1 found and corrected**; 6 residual risks |
| Test suite | **196 passed** (executed during this audit) |

**The three things most likely to go wrong in the viva**, in order: the missing Intent
Alignment Layer (§7.1), the absence of per-member contribution evidence in git (§8.2), and
the fact that four evaluation scripts have never been run (§7.2).

---

## 2. Mentor evaluation checklist — **BLOCKER**

| Row | Status |
|---|---|
| — | **No rows exist.** |

`docs/inputs/mentor-eval-2.md` does not exist. Confirmed by directory listing, `git ls-files`
and a user-profile search; the team has confirmed the data is unavailable.

**This is not "all mentor comments addressed" — it is "no mentor comments were available."**
The distinction matters: a panel asking "did you act on last evaluation's feedback?" cannot
be answered from this repository. `docs/MENTOR_EVAL_CHECKLIST.md` correctly remains in a
BLOCKED state rather than being populated speculatively.

**Action:** obtain the feedback and populate the checklist, or be prepared to state plainly
that the record was not available and describe the feedback from memory in the viva.

---

## 3. Approved objectives — coverage and claimed status

*Verbatim objectives are in §1.7. Every objective is discussed in at least two places.*

| Obj | Where quoted | Where mapped to code | Where status claimed | Claimed | Substantiated? |
|---|---|---|---|---|---|
| O1 Red Agent | §1.7 | §1.7.1 Table 1.4, §3.2.2 | §1.7.2, §5.1 Table 5.1, Slide 3, Slide 14 | 85% | ✓ code exists and is tested; **PII gap stated** |
| O2 Defender Agent | §1.7 | §1.7.1, §3.2.3–3.2.4 | §1.7.2, §5.1, Slide 3, Slide 14 | 90% | ✓ code exists and is tested; "clustering" wording qualified |
| O3a Enforcement engine | §1.7 | §1.7.1, §3.2.5, §4.4.4 | §1.7.2, §5.1, Slide 14 | 100% | ✓ three modes exist; **naming deviation disclosed** |
| O3b Verification loop | §1.7 | §1.7.1, §3.2.5 | §1.7.2, §5.1, §5.4 item 1 | 60% | ✓ code exists, **never executed — disclosed** |
| O4a Intent Alignment Layer | §1.7 | §1.7.1 (marked "no equivalent") | §1.7.2, §5.1.2, §5.4 item 5, Slide 15 | 0% | ✓ absence disclosed and argued |
| O4b Security Dashboard | §1.7 | §1.7.1, §4.3.2 | §1.7.2, §5.1.2, §5.4 item 8 | 60% | ✓ static-vs-live limitation disclosed |

**No objective is claimed complete on the strength of one half of a compound objective**, as
the proposal requires. ✓

---

## 4. References *(automated)*

- Bibliography: **27 entries, numbered [1]–[27] contiguously**, no gaps. ✓
- **Every entry [1]–[27] is cited at least once in the body text.** ✓
- **No in-text citation lacks a bibliography entry.** ✓
- One apparent orphan citation `[0]` was investigated and is a false positive — it is the
  Python expression `stronger[0]` inside Listing 4.1, not a citation.

**RISK — style conflict, unresolved by design.** `FORMAT_SPEC.md` records that the report
template's own reference examples (`Internet: URL, date [accessed]`, `vol. 38(4)`) contradict
the supplied IEEE style sheet (`[Online]. Available: URL`, `vol. 38, no. 4`). Appendix A
follows the **IEEE sheet** and states so in a note. If the department requires the template
form, entries [20] and [27] must be reformatted. Confirm before printing.

**RISK — 15 of 27 references are arXiv preprints**, marked as such. This is appropriate for
this field (CaMeL, spotlighting, MCPTox and Progent are all canonically preprints), but a
panel may ask why so few are peer-reviewed. The answer: 12 are peer-reviewed (USENIX
Security ×2, CCS, NDSS, ICLR ×2, NeurIPS, ACL Findings, EMNLP, SOSP, IEEE JSAC), and the
preprints are the canonical references for their systems.

---

## 5. Figures and tables *(automated)*

| Check | Result |
|---|---|
| Figures captioned with `FIGURE n.m:` format | 16 / 16 ✓ |
| Figures referenced by number in running text | 16 / 16 ✓ |
| Tables captioned with `TABLE n.m:` format | 24 / 24 ✓ |
| Tables referenced by number in running text | 24 / 24 ✓ |
| Every figure listed in LIST OF FIGURES | 16 / 16 ✓ |
| Every table listed in LIST OF TABLES | 24 / 24 ✓ |

**Defect found and fixed during this audit:** eleven tables (1.1, 1.2, 1.3, 1.6, 2.3, 2.5,
3.4, 4.1, 4.3, 5.1, 5.3) were captioned but never referenced by number in running text,
violating the template's explicit requirement — *"Do refer to figure/table numbers in the
running text also."* Introducing sentences were added to each. Re-verified: zero
unreferenced.

**RISK — deliberate deviation.** The template shows flat numbering (`TABLE 1`, `FIGURE 1`);
this report uses per-chapter numbering (`TABLE 2.3`). This was an explicit instruction and is
recorded in the working notes. Flag it to the mentor rather than letting the panel find it.

---

## 6. Outstanding markers

### 6.1 `[SCREENSHOT:]` — **BLOCKER**, 10 in submitted files

**The repository contains zero image files.** Every figure requiring a capture is currently
a dashed placeholder frame in the `.docx`.

| Location | Figure |
|---|---|
| `ch2_requirement_analysis.md:424` | §2.2.3.1 terminal UI |
| `ch2_requirement_analysis.md:429` | §2.2.3.1 HTML dashboard |
| `ch4_design_specifications.md:473` | Figure 4.7 terminal live table |
| `ch4_design_specifications.md:502, 504` | Figure 4.8 dashboard, verdict table |
| `ch4_design_specifications.md:522` | §4.4.1 agent server startup |
| `ch4_design_specifications.md:586` | §4.4.3 run summary |
| `ch4_design_specifications.md:635, 637` | §4.4.4 gateway block, audit |
| `SLIDE_SPEC.md:316, 318` | Slide 10 terminal + dashboard |

All ten are consolidated with capture instructions in `SCREENSHOT_MANIFEST.md`, ordered for a
single sitting. **§4.4 is titled "Snapshots of Working Prototype" and currently contains no
snapshots** — this is the most visible gap in the document.

*(Four further markers appear in `00_WORKING_NOTES.md` and `SCREENSHOT_MANIFEST.md`, which
are not submitted.)*

### 6.2 `[VERIFY:]` — 9 in submitted report files

| Location | Item | Severity |
|---|---|---|
| `front_matter.md:203` | ToC/LoF/LoT page numbers are placeholders | **BLOCKER** — must be regenerated from the assembled document |
| `ch2:180` | Literature allocation across team members is provisional | RISK |
| `ch2:545, 549` | Render hosting price, Azure OpenAI rates | RISK — cost figures |
| `ch3:343` | Per-member ownership in Table 3.3 | **BLOCKER** — see §8.2 |
| `appendix_a:116` | MCP specification revision not pinned | RISK |
| `appendix_b:3` | Plagiarism report not generated | **BLOCKER** |
| `00_WORKING_NOTES.md:139, 141` | Contribution basis, presentation split | Not submitted |

*(A further 15 `[VERIFY:]` markers in `SLIDE_SPEC.md` are all the presenter field, deliberately
left for the team to assign; 14 in `COST_INPUTS.md` are source-tracking, not submitted.)*

---

## 7. Claims versus what the code actually does

This section assumes a hostile reading of the source tree.

### 7.1 Verified: the report does **not** claim the Intent Alignment Layer exists

*(automated: `grep -ril "intent_align|semantic_compar|goal_align"` over `src/` and `scripts/`
returns zero matches.)*

The report states the absence in five places (§1.7.1 Table 1.4, §1.7.2, §5.1 Table 5.1,
§5.1.2, §5.4 item 5) and argues the substitution rather than concealing it. The demo script
and slide 15 both state it aloud.

**RISK — this is still the question you will be asked.** The prepared answer is in
`DEMO_SCRIPT.md` §4. Do not improvise it.

### 7.2 Verified: unrun experiments are described as unrun

Four scripts exist and have never been executed: `adaptive_attack_eval.py`,
`tool_poisoning_eval.py`, `defense_baseline_eval.py`, `benchmark_models.py`. Every mention in
the report labels them as code-complete-but-unexecuted (§1.9 Table 1.6 rows 8 and 15, §3.3
Table 3.3, §4.4.5, §5.1 Table 5.1, §5.4 items 1–3, 15). ✓

**RISK:** §2.2.4.1 requirement P1 quotes a 25-minute run time that is **extrapolated** from a
269.93-second run at a lower iteration budget, not measured. The table says so. If asked
"how long does a run take?", the honest answer is "we've measured 4.5 minutes at
`max_iterations=2` and extrapolated 25 minutes at 6 — we haven't measured the latter."

### 7.3 Defect found and corrected during drafting

An earlier draft derived six objectives from repository evidence and reported **85%
completion**. The panel-approved objectives are materially different — they specify an Intent
Alignment Layer, a Security Dashboard and a PII risk category that the code does not
implement as described. That figure was **void** and has been replaced throughout by **71%**.
*(automated: no artifact now contains "85%" as a completion figure.)*

### 7.4 Residual risks — claims a hostile reader could challenge

| # | Claim in the report | Challenge | Report's defence |
|---|---|---|---|
| 1 | "Three response modes (BLOCK, WARN, LOG)" per O3 | The code implements `BLOCK`, `AUDIT`, `REQUIRE_CONFIRMATION` — **the names do not match the proposal** | Disclosed in §1.7.1 with an explicit mapping; `REQUIRE_CONFIRMATION` noted as *stronger* than WARN. **Be ready to say this before the panel points at it.** |
| 2 | O2 "clusters vulnerability patterns" | The code performs classification into five types plus aggregation — **not unsupervised clustering** | §3.2.3 and §5.1 both qualify the wording. Do not use the bare word "clustering" in the viva. |
| 3 | "Benign pass rate 0.94, no degenerate deny-all" | Benign suites are **hand-authored** — the same authors wrote the task and its expected calls | Disclosed as a validity threat in §3.1.5 and risk R6; recorded-provenance tooling exists but has never been run |
| 4 | Policy coverage figures | The policy is **LLM-generated**; coverage is measured, not proven | Stated in §1.4 scope exclusion 5, §5.2, and the working-notes caveats |
| 5 | Gateway "enforces the policy at runtime" | Enforcement is **post-hoc** — the inner agent completes its trajectory first | Disclosed in §4.4.4 with Figure 4.9 and booked as future work item 11 |
| 6 | Measured coverage reflects live behaviour | **IFC-002 is in the verifier but not the gateway** — the two paths enforce different policies | Disclosed in §5.1.3 defect 1 and risk R4; measured figures explicitly called an upper bound |

---

## 8. Consistency checks *(automated)*

### 8.1 The completion figure — ✓ consistent

| Artifact | Location | Value |
|---|---|---|
| Abstract | `front_matter.md` | 71% |
| Report §1.7.2 | Table 1.5 + prose | 71% (85+90+80+30)/4 |
| Report §5.1 | Table 5.1 + prose | 71% |
| Slide 3 | objectives table | 71% |
| Slide 14 | summary block + chart | 71% |
| Working notes | §1 | 71% |
| Design prompt, Slide 14 | summary block | 71% |

Sub-deliverable values (85 / 90 / 100 / 60 / 0 / 60) are identical in §1.7.2, §5.1 Table 5.1,
Figure 5.1, Slide 14's chart JSON and the Slide 14 design prompt. ✓

Status counts reconcile: **1 complete + 4 in progress + 1 not started = 6 sub-deliverables**,
consistent between Slide 14's chart and its summary block. ✓

### 8.2 Per-member contribution — **BLOCKER**

**All 14 commits in the repository carry a single author.** There is no per-member split
derivable from version control.

The report handles this correctly — Table 3.3's ownership column is explicitly labelled as
coming from the team's proposal-stage role allocation and *not* from commit history, and
§1.5 constraint 7 states the limitation. But:

**If the panel opens `git log`, they will see one author across a five-member project.** This
is the single most likely source of an uncomfortable question. Prepare an answer, and
populate the contribution basis before submission. Slide 14's per-member split is currently a
placeholder.

### 8.3 Other cross-artifact consistency — ✓

- Corpus figures in §5.1 Table 5.2 match `RESULTS_corpus_v1.md` exactly, including the
  non-final caveat. ✓
- Slide 11's chart JSON matches §5.1 Table 5.2 for all ten tools. ✓
- Cost figures (₹786 / ₹1,612 / ₹3,865 / ₹4,756) identical in §2.3 Table 2.6, §5.3, Slide 13
  chart JSON and the Slide 13 design prompt. ✓
- LOC figures (16,802 / 9,397 / 3,988 / 3,417) consistent between §1.1, §5.1.1 and Slide 11. ✓

---

## 9. Format compliance against `FORMAT_SPEC.md`

*(verified against the generated `CapstoneMidTermReport.docx`)*

| Requirement | Status |
|---|---|
| A4 portrait | ✓ 8.27 × 11.69 in |
| Margins 1″ top/bottom/right, 1.5″ left | ✓ |
| Times New Roman throughout | ✓ Normal style |
| Chapter names 16 pt bold | ✓ 7 chapter headings, right-aligned caps with rule |
| Headings 14 pt bold | ✓ |
| Body 12 pt | ✓ |
| Table content 10 pt | ✓ 38 tables |
| Captions 10 pt | ✓ |
| Line spacing 1.5 | ✓ |
| Page numbers bottom centre | ✓ PAGE field in footer |
| Roman front matter, arabic body restarting at 1 | ✓ two sections |
| Table captions above, figure captions below | ✓ |
| Mandatory 5-chapter structure + Appendix A/B | ✓ |
| §1.1 3–4 pages | **VERIFY after pagination** |
| §1.2 1 page | **VERIFY after pagination** |
| §1.3 ≥5 research gaps with references | ✓ 7 gaps, all cited |
| §2.1.3 ~6 papers per member | ✓ 26 papers across 5 members (4–6 each) |
| §3.1 2–3 pages, §3.2 2–3 pages | **VERIFY after pagination** |

### 9.1 Unresolved format conflicts — carried forward, **not** silently decided

`FORMAT_SPEC.md` records seven conflicts between the template and the guidelines. None was
resolved unilaterally. Three affect this document materially:

1. **Front-matter page numbers** — the template's printed numerals disagree with its own ToC
   (ABSTRACT printed ii but listed i, etc.). The build uses roman numerals from i.
2. **LIST OF TABLES / LIST OF FIGURES order** — the template's physical pages and its ToC
   disagree. This report follows the **ToC** order (Figures before Tables).
3. **Reference-section heading** — "REFERENCES" (guidelines) vs "APPENDIX A: References"
   (template). This report follows the **template**.
4. **Page-numbering format string** — genuinely absent from the source document; position
   (bottom centre) is certain, format is not.

**Action:** raise all four with the mentor in one message rather than guessing.

---

## 10. Manual steps required before submission

The `.docx` is generated but **not print-ready**. In order:

1. **BLOCKER** — Capture all 10 screenshots per `SCREENSHOT_MANIFEST.md` and paste into the
   dashed frames.
2. **BLOCKER** — Render the 16 Mermaid diagrams and paste into the MERMAID placeholder
   frames. The build script cannot render them (no renderer available in this environment);
   use the Mermaid Live Editor and export PNG at 2× scale.
3. **BLOCKER** — Replace the static ToC / LoF / LoT with live Word fields, then update all
   fields (Ctrl+A, F9) to generate real page numbers.
4. **BLOCKER** — Populate the contribution basis and per-member ownership (Table 3.3,
   Slide 14).
5. **BLOCKER** — Run the plagiarism check and insert the report into Appendix B.
6. Verify the page-length requirements flagged in §9 once pagination is real.
7. Obtain mentor and co-mentor counter-signatures on the Declaration.
8. Confirm the four format conflicts in §9.1 with the department.
9. Re-run this audit after steps 1–5.

---

## 11. What a hostile panel will find that the report does not hide

Listed so that nothing here is a surprise in the room:

1. The Intent Alignment Layer, an approved deliverable, **does not exist**. (§5.1.2)
2. Four evaluation scripts have **never been run**; there is no measured risk-reduction
   figure. (§5.1.2, §5.4)
3. The headline corpus results are **n = 3** with standard deviations up to ±0.58. (§5.1
   Table 5.2)
4. `git log` shows **one author** for a five-member project. (§8.2)
5. The live gateway and the offline verifier **enforce different policies**. (§5.1.3)
6. No HTTP endpoint on any of the three servers is **authenticated**. (§5.1.3)
7. The grader heuristic can score 0.96 and **override the model judge** at the default
   threshold. (§5.1.3)
8. `requests` is imported but **undeclared** — a clean install can break. (§5.1.3)
9. Benign task suites are **hand-authored**, so the utility measurement is partly circular.
   (§3.1.5)
10. No CI exists, so the 196 tests have **never been run automatically**. This audit executed
    them: `python -m pytest tests/ -q` → **196 passed in 10.11 s** (19 August 2026). The
    suite is green; what is missing is automation, not correctness. Note that `cli.py`,
    `hardening.py`, `output/report.py`, `llm_provider.py`, `settings.py` and `manifest.py`
    have **zero test coverage**, and no end-to-end test of `analyze` or `harden` exists —
    so a green suite is weaker evidence than the count of 196 suggests.

Item 10 is the cheapest remaining fix: adding a CI workflow that runs pytest, ruff and mypy
takes under an hour and converts a green local run into standing evidence.
