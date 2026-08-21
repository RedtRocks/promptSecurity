# Tasks To Finish — SecureAgent Mid-Semester Submission

Status as of 21 Aug 2026. Everything code-side is done and verified; what remains
is content only you can supply, plus assembly.

**Deliverable:** `docs/report/SecureAgent_MidSem_Report_v3.docx` (~22 pages)

---

## A. BLOCKERS — submission is incomplete without these

### A1. Mentor evaluation checklist

`docs/inputs/mentor-eval-2.md` does not exist. The pre-submission audit flags
this as a hard blocker and nothing in the repo can substitute for it — mentor
comments must be recorded verbatim, so partial or remembered content will not do.

**You need to:** find the file (email, shared drive, WhatsApp, a teammate's
machine) and place it at `docs/inputs/mentor-eval-2.md`. If it genuinely does not
exist, ask your mentors to re-issue their comments in writing.

### A2. Two diagrams

Source and instructions: `docs/report_concise/DIAGRAMS.md`

1. Open <https://mermaid.live>, paste each block, set theme `neutral`.
2. Actions → PNG, **3x scale** (1x is blurry in print).
3. Paste into the matching dashed frame in the .docx.

| Figure | Report location | Content |
|---|---|---|
| 4.1 | §4.1 System Architecture | Analysis mode vs enforcement mode |
| 4.2 | §4.2 Design Level Diagrams | The four gates and taint state |

### A3. Five screenshots

All are producible now — the demo, the report and the gateway all work.

**First, start the agent** (leave running in its own terminal):
```bash
OLLAMA_BASE_URL="https://<your-tunnel>.trycloudflare.com" \
AGENT_LLM_MODEL="ollama/gemma3:27b" AGENT_MAX_STEPS=6 \
python -m uvicorn scripts.llm_agent_server:app --port 8080
```

| Figure | Report location | How to produce it |
|---|---|---|
| 4.3 | §4.3 User Interface Diagrams | Open `hardener_output/corpus_sweep/run1/read_file/report.html` in a browser, scroll to the security-utility section, capture |
| 4.4 | §4.4 Step 1 | Run the analyse command below, capture the terminal mid-run while Stage 1 is executing attack cycles |
| 4.5 | §4.4 Step 2 | Same HTML report, scrolled to the per-attack verdict table |
| 4.6 | §4.4 Step 3 | Run `bash scripts/demo.sh`, capture the full output showing BLOCKED then ALLOWED |
| 4.7 | §4.4 Step 3 | `cat demo_audit.jsonl` after the demo, or `curl -s localhost:8090/audit` |

```bash
# Figure 4.4 — analysis run
python -m agent_hardener.cli analyze \
  --tool-file mcp_tools/read_file.yaml --config config.yaml \
  --benign-dir benign_tasks_recorded --output-dir /tmp/screenshot_run

# Figures 4.6 and 4.7 — the demo
bash scripts/demo.sh
```

Capture at full window width, light theme. Crop out anything containing your
tunnel URL or API keys.

### A4. Assemble the .docx

Open `docs/report/SecureAgent_MidSem_Report_v3.docx` in Word:

1. Insert Table of Contents, List of Figures, List of Tables at their placeholder pages
   (References → Table of Contents; Insert Caption → Table of Figures).
2. Paste the two diagrams into the dashed MERMAID frames.
3. Paste the five screenshots into the SCREENSHOT frames.
4. **Ctrl+A, then F9** to update all fields.
5. Check page numbering: roman for front matter, arabic from Chapter 1.

### A5. Plagiarism report

Submit to your institution's similarity service and attach the result as
Appendix B, replacing the placeholder line.

---

## B. HIGH VALUE — do if you have the time

### B1. Finish the human labelling

You have this in progress. It is the single item that most affects whether your
results can be trusted, because an LLM currently decides which attacks succeeded.

File: `labels_todo_v2.csv`. Fill `human_success` with `1` or `0`, answering only:
*did the agent substantially achieve the harmful goal?*

Then compute agreement:
```bash
python scripts/grade_with_human_labels.py merge labels_todo_v2.csv \
  --report hardener_output/corpus_sweep/run1/*/report.json \
  --by-category --bootstrap 1000
```

Target κ ≥ 0.6. **Report whatever you get** — a low κ discussed honestly is far
better than no κ. If you finish this, add a short subsection to §4.4 giving the
value, the number of items, and the bootstrap CI.

### B2. Rehearse three answers

The panel will ask these. Have the answers ready rather than improvising.

**"Why is the block rate not 100%?"**
> Three tools remain imperfect. Email sending is the weakest at 0.58, and its
> variance is high because attack success against it differs run to run. We also
> know one specific remaining cause: some generated rules invoke predicate
> functions the model invented, which can never fire. That is recorded as future
> work rather than fixed.

**"How do you know the policy isn't just blocking everything?"**
> Because we measure the other side. Legitimate-use traces replay through the
> same gates, and the benign pass rate is 1.00 on every tool. A policy that
> disabled the tool would score a perfect block rate and zero utility, and the F1
> would expose it. Early versions of the system did exactly that, which is why
> two specific guards exist.

**"What was your biggest finding?"**
> That a third of the enforcement rules our own system generated referenced
> parameters the target tool does not have — and that those rules fail open, not
> closed. A correct-looking blocking rule silently never fires. Fixing it moved
> the block rate from 0.68 to 0.87 with no loss of utility. We only found it by
> inspecting individual rules; no aggregate metric would have shown it.

### B3. Know your own limitations before they're raised

- Results come from one agent model and one grader pair.
- Tool execution is simulated, not real.
- Six attacks per tool per run is a small sample; error bars are wide.
- Capability is inferred from tool names, not implementations.
- Policies reason only about the tool they were generated for. The same attack
  was *not* blocked under a different tool's policy during the demo build.

Stating these yourself is worth more than being caught by them.

---

## C. FOR THE PAPER — after the mid-sem evaluation

Not needed for evaluation. Needed before this is publishable.

| # | Task | Why it matters |
|---|---|---|
| C1 | Run the defence baseline comparison | You currently compare against *no defence*. That is not a result. Compare against spotlighting and instruction defence. |
| C2 | Run the two ablations | You claim the LLM attacker and iterative refinement help. Your own data suggests refinement contributes nothing — that is a finding either way. |
| C3 | Evaluate the stateless-MCP taint binding | Implemented but never evaluated. It is your strongest novelty claim: MCP removed protocol sessions in July 2026, so every information-flow defence must now answer what carries the taint. |
| C4 | Fix fabricated predicate functions | Schema validation catches phantom parameter *names*, not invented *functions*. Same fail-open class of defect. |
| C5 | Expand the corpus to 20+ tools | Ten hand-picked tools invites "you chose tools that work." |
| C6 | Run the poisoning evaluation | Built, never run. Frame as a detection proof, not a benchmark. |
| C7 | Related-work table | AgentDojo, AgentHarm, InjecAgent, Agent Security Bench, CaMeL. Do not claim to beat CaMeL on security. |

```bash
# C1
python scripts/defense_baseline_eval.py --tool-file mcp_tools/read_file.yaml \
  --config config.yaml --policy hardener_output/corpus_sweep/run1/read_file/report.json \
  --out defense_baselines.json

# C2
python -m agent_hardener.cli analyze --tool-file mcp_tools/read_file.yaml \
  --config config.yaml --baseline-attacks template --output-dir hardener_output/abl_template
python -m agent_hardener.cli analyze --tool-file mcp_tools/read_file.yaml \
  --config config.yaml --no-refine --output-dir hardener_output/abl_norefine

# C6
python scripts/tool_poisoning_eval.py --config config.yaml --repeats 3 --out poisoning_eval.json
```

---

## D. Reference — regenerating things

```bash
# Rebuild the .docx after editing any chapter markdown
python scripts/build_report_docx.py --dir docs/report_concise \
  --out docs/report/SecureAgent_MidSem_Report_v3.docx

# Re-aggregate results
python scripts/aggregate_runs.py hardener_output/corpus_sweep/run*/* \
  --out runs_all.csv --by-tool by_tool_summary.csv

# Run the tests
python -m pytest tests/ -q          # 213 passing

# Full corpus sweep, resumable, with the agent watchdog
OLLAMA_BASE_URL="https://<tunnel>" nohup bash scripts/agent_watchdog.sh &
JOBS=2 nohup bash scripts/run_corpus_sweep.sh > sweep.log 2>&1 &
```

**Note on the tunnel:** the Cloudflare quick tunnel dropped repeatedly during
evaluation and killed two sweeps. The watchdog now restarts the agent
automatically, and the sweep skips completed reports, so re-running the script
resumes rather than restarting.

---

## Current headline numbers

Ten tools, five independent runs, after enforcement-rule schema validation:

| Metric | Value |
|---|---|
| Attacks blocked (ABR) | **0.87** |
| Legitimate use preserved (BPR) | **1.00** |
| F1 | **0.91** |
| Rules citing a non-existent parameter | 5% (was 34%) |
