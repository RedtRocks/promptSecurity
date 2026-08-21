# Screenshot Capture Manifest

Every `[SCREENSHOT:]` marker from the report and the slide spec, consolidated and ordered so
the whole set can be captured in **one sitting** without restarting services.

**The repository currently contains zero image files.** All eleven captures below are
outstanding.

---

## Before you start

### Environment

| # | Command | Confirm |
|---|---|---|
| 1 | Start inference backend (Ollama, plus `cloudflared tunnel --url http://localhost:11434` if remote) | `curl $OLLAMA_BASE_URL/api/tags` returns JSON |
| 2 | `OLLAMA_BASE_URL=... AGENT_LLM_MODEL=ollama/gemma3:27b AGENT_MAX_STEPS=6 python -m uvicorn scripts.llm_agent_server:app --port 8080` | `curl http://localhost:8080/` lists 10 tools |
| 3 | Have a completed run in `hardener_output/<tool>/` with both `report.json` and `report.html` | Files exist |
| 4 | `agent-hardener gateway --policy hardener_output/<tool>/report.json --agent-endpoint http://localhost:8080 --port 8090 --audit-log hardener_output/gateway_audit.jsonl` | `curl http://localhost:8090/health` returns policy name |

### Capture settings

- **Terminal:** dark background, monospace, window width ≥ 120 columns, font large enough to
  read when projected. Do not capture the full desktop — crop to the terminal window.
- **Browser:** light theme, zoom 100%, hide bookmarks bar, crop out browser chrome where the
  content allows.
- **Format:** PNG. Save into `docs/images/`.
- **Redact before saving:** any API key, bearer token, tunnel URL, or absolute path
  containing a personal username. Several of these appear in startup banners.

### Ordering logic

Group A is captured during a single live analyse run — **you cannot pause it**, so read
group A end to end before starting. Groups B and C are static and can be captured any time
afterwards. Group D needs the gateway running.

---

## Group A — During a live analysis run

Start the run, then capture A1 and A2 while it is in flight, and A3 when it finishes.

```bash
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml
```

### A1 · `fig_4_7_terminal_live.png`
- **Used in:** Report §4.3.1 (Figure 4.7), Slide 10
- **Open:** the terminal running the analyse command
- **State:** mid-run, Rich live table populated
- **Must be visible:** at least three attacks in **distinct** states — one `SUCCESS`, one
  `REFUSED`, one `RUNNING` with a partial score; the objective and technique columns; the
  attempt counter showing progress (e.g. `3/6`)
- **Note:** this is the hardest shot to get. Watch for the moment the table has mixed states
  and capture immediately — states change every few seconds.

### A2 · `slide10_terminal.png`
- **Used in:** Slide 10
- **Open:** same terminal
- **State:** same as A1 but framed tighter — table only, no scrollback
- **Must be visible:** the table with mixed states, cropped to be legible when projected
- **Note:** if A1 came out well, crop it rather than waiting for another moment.

### A3 · `fig_4_10_run_summary.png`
- **Used in:** Report §4.4.3
- **Open:** same terminal, after the run completes
- **State:** final summary printed
- **Must be visible:** attack success rate, policy coverage, and the **ABR / BPR / F1 line
  together in one frame**
- **Note:** this is the single most important terminal capture — it is the headline
  measurement.

---

## Group B — Agent server startup

Capture from the terminal started in setup step 2. If it has scrolled, restart it.

### B1 · `fig_4_9_agent_start.png`
- **Used in:** Report §4.4.1
- **Open:** the agent server terminal
- **State:** freshly started
- **Must be visible:** the uvicorn startup lines, the port (8080), and the log line showing
  the tool count loaded from the corpus
- **Redact:** `OLLAMA_BASE_URL` if it contains a live tunnel hostname

---

## Group C — HTML report (static, no services needed)

Open the completed `report.html` from your run. If the live run failed, use
`sample_report/report.html` — but note in the caption that it is sample data.

### C1 · `fig_4_8_dashboard.png`
- **Used in:** Report §4.3.2 (Figure 4.8), Slide 10
- **Open:** `report.html` in a browser
- **State:** scrolled so the headline metrics band and the Stage 3 security/utility panel are
  in the same frame
- **Must be visible:** **ABR, BPR and F1 together**, plus the tool name
- **Note:** if they will not fit in one viewport, zoom to 80% rather than taking two shots —
  the point of this figure is the three numbers side by side.

### C2 · `slide10_dashboard.png`
- **Used in:** Slide 10
- **Open:** same page
- **State:** same region, cropped tighter for projection
- **Must be visible:** the three metrics, legible at slide size
- **Note:** reuse C1 cropped if it is clean.

### C3 · `fig_4_8b_verdicts.png`
- **Used in:** Report §4.3.2
- **Open:** same page, scrolled to the per-record verifier verdict table
- **Must be visible:** at least four rows with **differing** `final_status` values — ideally
  `BLOCKED`, `AUDITED` and `UNMITIGATED` all present, plus the triggered rule IDs column
- **Note:** this figure exists to prove the numbers are auditable. If every row shows the same
  status, pick a different run's report.

---

## Group D — Gateway enforcement

Requires the gateway from setup step 4. Have `attack_prompt.json` and `benign_prompt.json`
prepared as described in `DEMO_SCRIPT.md` §1.2.

### D1 · `fig_4_11_gateway_block.png`
- **Used in:** Report §4.4.4
- **Open:** two terminals side by side — left running the gateway, right ready for curl
- **State:** after sending the attack prompt to `http://localhost:8090/run`
- **Must be visible:** the gateway's startup banner on the left; on the right, a JSON response
  containing a **non-empty `enforcement_log`**, the blocked call marked failed, and
  `refusal_detected: true`
- **Command:**
  ```bash
  curl -s -X POST http://localhost:8090/run -H 'Content-Type: application/json' \
    -d @attack_prompt.json | python -m json.tool | head -40
  ```
- **Note:** pipe through `head` as shown — an untruncated trajectory will not fit on screen.

### D2 · `fig_4_12_audit.png`
- **Used in:** Report §4.4.4
- **Open:** terminal or browser
- **State:** after D1, so there is at least one blocked event recorded
- **Must be visible:** at least **two** audit events, one with `"blocked": true`
- **Command:** `curl -s "http://localhost:8090/audit?limit=5" | python -m json.tool`
- **Note:** send the benign prompt too before capturing, so the log shows both a blocked and
  an allowed event — the contrast is the point.

### D3 · `demo_benign_pass.png` *(optional but recommended)*
- **Used in:** Slide 12 speaker support; useful as a demo fallback image
- **State:** after sending the benign prompt through the gateway
- **Must be visible:** successful tool calls with an **empty** `enforcement_log`
- **Note:** capture this even though no marker in the report requires it. If the live demo
  fails on the utility step, this image saves the argument.

---

## Capture checklist

| ID | Filename | Group | Used in | Captured |
|---|---|---|---|---|
| A1 | `fig_4_7_terminal_live.png` | Live run | Report Fig 4.7, Slide 10 | ☐ |
| A2 | `slide10_terminal.png` | Live run | Slide 10 | ☐ |
| A3 | `fig_4_10_run_summary.png` | Live run | Report §4.4.3 | ☐ |
| B1 | `fig_4_9_agent_start.png` | Server | Report §4.4.1 | ☐ |
| C1 | `fig_4_8_dashboard.png` | Report HTML | Report Fig 4.8, Slide 10 | ☐ |
| C2 | `slide10_dashboard.png` | Report HTML | Slide 10 | ☐ |
| C3 | `fig_4_8b_verdicts.png` | Report HTML | Report §4.3.2 | ☐ |
| D1 | `fig_4_11_gateway_block.png` | Gateway | Report §4.4.4 | ☐ |
| D2 | `fig_4_12_audit.png` | Gateway | Report §4.4.4 | ☐ |
| D3 | `demo_benign_pass.png` | Gateway | Slide 12 / demo fallback | ☐ |

## After capture

1. Save all files into `docs/images/`.
2. Re-check each for leaked keys, tokens, tunnel URLs and personal paths.
3. Replace the `[SCREENSHOT: ...]` markers in `ch4_design_specifications.md` and
   `SLIDE_SPEC.md` with image references.
4. Confirm every figure that now has an image is listed in the LIST OF FIGURES with its
   caption.
5. Re-run the pre-submission audit — outstanding screenshot markers are one of its checks.
