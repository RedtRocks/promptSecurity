# SecureAgent — 4-Minute Technical Demo Script

**Total budget: 4:00.** Timings below are cumulative. If you are more than 20 seconds over
at any checkpoint, use the recovery note for that step.

**The demo's single job:** show that an attack succeeds against the unguarded agent, that a
policy is synthesised from that attack, and that the same attack is then blocked while a
legitimate task still passes. Everything else is optional.

---

## 1. Pre-demo setup

Complete all of this **before** the panel is in the room. Nothing here is demoed live.

### 1.1 Services to start (in order)

| # | Command | Startup time | Confirm it worked |
|---|---|---|---|
| 1 | Start the inference backend. If using a remote GPU: `cloudflared tunnel --url http://localhost:11434` on the GPU host, then copy the `*.trycloudflare.com` URL into `config.yaml` as `ollama_base_url`. | 10–20 s | `curl $OLLAMA_BASE_URL/api/tags` returns a JSON tool list |
| 2 | `OLLAMA_BASE_URL=... AGENT_LLM_MODEL=ollama/gemma3:27b AGENT_MAX_STEPS=6 python -m uvicorn scripts.llm_agent_server:app --port 8080` | 5–10 s | `curl http://localhost:8080/` returns `{"status": ..., "tools": [...]}` with 10 tools |
| 3 | `agent-hardener gateway --policy hardener_output/read_file/report.json --agent-endpoint http://localhost:8080 --host 127.0.0.1 --port 8090 --audit-log hardener_output/gateway_audit.jsonl` | 2–3 s | `curl http://localhost:8090/health` returns the policy tool name and rule counts |

### 1.2 Seed data required

- **A completed analysis run** for one tool, with `report.json` and `report.html` on disk.
  Use `read_file` or `database_query` — both produce visible enforcement rules.
  **Do not generate this live.** A full run takes ~25 minutes at `max_iterations: 6`.
- **A known-successful attack prompt** copied out of that run's `report.json` into a text
  file you can paste from. Find it by locating a record with `final_score` above the
  threshold and copying its `final_prompt_used`.
- **A benign task prompt** for the same tool, taken from `benign_tasks/<tool>.yaml`.
- `sample_report/report.html` as a fallback if the live report fails to open.

### 1.3 Tabs and windows to arrange

| Position | Content |
|---|---|
| Terminal 1 (left, large) | Gateway running, logs visible |
| Terminal 2 (right, large) | Empty prompt, working directory `capstone/`, ready for curl |
| Browser tab 1 | The completed `report.html`, pre-scrolled to the security/utility panel |
| Browser tab 2 | `report.json` open, pre-scrolled to `enforcement_rules` |
| Editor tab | The attack prompt and benign prompt, ready to copy |

### 1.4 Pre-flight checks (run these 5 minutes before)

```bash
curl -s http://localhost:8080/ | head -c 200          # agent alive, tools loaded
curl -s http://localhost:8090/health                   # gateway alive, policy loaded
curl -s http://localhost:8090/policy | head -c 300     # policy actually parsed
```

All three must return JSON. If any fails, fix it now — none of these is recoverable live.

---

## 2. The demo

### Step 1 — Frame the problem (0:00 → 0:25)

**Do:** Show `mcp_tools/read_file.yaml` in the editor. Point at the `description` field.

**Say:**
> "This is a tool definition from a third-party MCP server. The agent reads this description
> as trusted instructions — but whoever runs that server wrote it. OWASP calls this tool
> poisoning. Our system assumes this text is hostile and probes it to find out what the tool
> can actually be abused for."

**Evidences:** Objective 1 — the threat model the Red Agent targets.

---

### Step 2 — Show the attack succeeding, unguarded (0:25 → 1:10)

**Do:** In Terminal 2, send the known-successful attack prompt directly to the agent on
port **8080** — bypassing the gateway.

```bash
curl -s -X POST http://localhost:8080/run \
  -H 'Content-Type: application/json' \
  -d @attack_prompt.json | python -m json.tool | head -40
```

**Say:**
> "This goes straight to the agent, no policy. Watch the tool calls — it reads the sensitive
> file, then sends it out. The agent didn't refuse; it was persuaded. This attack came out of
> our Stage 1 red-teaming: six misuse objectives crossed with eight escalating techniques, and
> when the agent refuses, the refiner escalates to a stronger technique instead of giving up."

**Point at:** the `tool_calls` array showing the read followed by the exfiltration sink, and
`refusal_detected: false`.

**Evidences:** Objective 1 — schema-aware attack generation with escalation on refusal.

---

### Step 3 — Show the synthesised policy (1:10 → 1:50)

**Do:** Switch to browser tab 2, `report.json` at `enforcement_rules`.

**Say:**
> "That successful attack became evidence. Stage 2 classified why it worked — which of five
> exploit types — and Stage 3 compiled it into a policy: confidentiality levels, capability
> limits, taint rules, and enforcement rules with three response modes. This is generated, not
> hand-written. And note the rule triggers on argument values, not just the tool name — so it
> blocks that query, not every query."

**Point at:** one enforcement rule, its `trigger_condition`, and its `action`.

**Evidences:** Objective 2 — autonomous synthesis of a machine-enforceable policy.
Objective 3a — three response modes.

---

### Step 4 — Show the same attack blocked (1:50 → 2:40)

**Do:** Send the **identical** prompt to the gateway on port **8090**.

```bash
curl -s -X POST http://localhost:8090/run \
  -H 'Content-Type: application/json' \
  -d @attack_prompt.json | python -m json.tool | head -40
```

**Say:**
> "Same prompt, same agent — but now behind the policy gateway. The enforcement log shows
> which gate fired and at which step. The critical thing: this decision involved no language
> model. It's deterministic replay, so it holds even when the model has been jailbroken. That's
> the property we can defend that a prompt-level defense cannot."

**Point at:** the non-empty `enforcement_log`, the blocked call rewritten as failed, and
`refusal_detected: true`.

**Evidences:** Objective 3a — runtime enforcement. Objective 3b — verification loop.

---

### Step 5 — Show utility is preserved (2:40 → 3:20)

**Do:** Send the **benign** prompt to the gateway on port 8090.

```bash
curl -s -X POST http://localhost:8090/run \
  -H 'Content-Type: application/json' \
  -d @benign_prompt.json | python -m json.tool | head -30
```

**Say:**
> "This is the part that matters. A policy that blocks everything blocks every attack — and
> destroys the tool. This legitimate task still goes through, empty enforcement log. That's why
> we report the harmonic mean of block rate and benign pass rate: a deny-all policy scores
> zero. Across the ten-tool corpus our benign pass rate averages 0.94, and no policy has been
> flagged degenerate."

**Point at:** empty `enforcement_log`, successful tool calls.

**Evidences:** Objective 3b — the security/utility tradeoff measurement.

---

### Step 6 — Dashboard and honest status (3:20 → 4:00)

**Do:** Switch to browser tab 1, the security/utility panel of `report.html`.

**Say:**
> "Everything you just saw is in the report — risk scores, the active policy, and a per-record
> verdict table so any of these numbers can be audited rather than trusted. Two honest caveats.
> These corpus figures are from three runs, not five, and some standard deviations exceed
> ±0.5 — the mechanism is demonstrated, the exact protection level isn't yet quantified. And
> the Intent Alignment Layer from our approved objectives isn't built: we substituted
> deterministic information-flow gates, which buy us independence from model compliance but
> lose semantic coverage. That's the main item in our future work."

**Evidences:** Objective 4b — the dashboard, honestly scoped.

---

## 3. The three highest-risk failure points

### Risk 1 — The live agent hangs or the inference backend times out

**Likelihood: high.** This is the most probable failure. The tunnel can drop, the GPU host
can be busy, and a 27B model under load can exceed the 120-second client timeout.

**Symptom:** Step 2 or Step 4 hangs for more than ~15 seconds with no output.

**Fallback, in order:**
1. Ctrl-C. Say: *"The model is on a shared GPU — let me show you the recorded run instead."*
2. Open `report.json` in browser tab 2 and read the **stored** trajectory for that exact
   attack record: `attack_trajectory[-1].trajectory.tool_calls`. This is the same evidence,
   captured earlier.
3. Then jump straight to Step 3. The narrative still works — you lose the live element, not
   the argument.

**Prevention:** run Step 2 and Step 4 once, five minutes before the demo, to warm the model.

---

### Risk 2 — The attack does not succeed on this run

**Likelihood: medium.** Model output is non-deterministic. The prompt that succeeded during
your recorded run may be refused live.

**Symptom:** Step 2 returns `refusal_detected: true` or an empty `tool_calls` array.

**Fallback:**
1. Do **not** retry — it burns 30 seconds and may fail again.
2. Say: *"Interesting — it refused this time. That's genuine non-determinism, and it's exactly
   why we report mean and standard deviation across repeated runs rather than single numbers.
   Here's the run where it succeeded."*
3. Show the stored trajectory from `report.json` as in Risk 1.

This turns the failure into a methodology point rather than a broken demo. Rehearse saying it
calmly.

---

### Risk 3 — The gateway rejects the policy at startup

**Likelihood: low, impact total.** If `report.json` has an unexpected shape, the gateway
exits and Steps 4–5 are impossible.

**Symptom:** `curl http://localhost:8090/health` fails during pre-flight.

**Fallback:**
1. Re-launch pointing at a known-good policy file from an earlier run directory.
2. If no policy loads at all, demo enforcement **offline** instead: run the verifier over the
   stored trajectory and show the verdict. Say: *"I'll show the enforcement decision through
   the verifier directly — it's the same gate logic the gateway runs."*
3. Have the command for this ready in your editor tab, not typed from memory.

**Prevention:** this is why §1.4 pre-flight includes `curl /policy`, not just `/health`.

---

## 4. Likely panel questions, with prepared answers

**Q: "Is the policy itself generated by an LLM? How do you know it's correct?"**
> Yes — the policy is LLM-generated, and we don't claim correctness. We claim it's *measured*.
> The verifier that evaluates it is fully deterministic — no model call — so every coverage
> number is reproducible and every per-record verdict ships in the report for audit. An
> over-broad policy shows up immediately as a fall in benign pass rate. That's the check.

**Q: "What stops it just disabling the tool and claiming 100% security?"**
> That exact failure happened repeatedly in development, which is why two guards exist. One
> restores any capability the profile says the tool genuinely uses; the other downgrades a
> block rule that would fire on every call to a confirmation rule. And the headline metric is
> the harmonic mean of block rate and benign pass rate, so a deny-all policy scores zero
> rather than perfect.

**Q: "How is this different from CaMeL?"**
> CaMeL is stronger on security and we don't claim otherwise — its guarantee holds by
> construction. But it requires rewriting the agent around a custom interpreter and a
> split privileged/quarantined model. Ours wraps an unmodified agent at the dispatch boundary
> and synthesises the policy automatically per tool, and we treat the tool *description* as
> untrusted, which CaMeL's threat model doesn't cover. Different operating point, not a better
> guarantee.

**Q: "Where is the Intent Alignment Layer from your approved objectives?"**
> Not built — that's our largest gap and it was an architectural decision. We replaced semantic
> goal-versus-action comparison with deterministic information-flow gates. The gain is that the
> gates hold when the model has been jailbroken; an LLM-based intent comparator wouldn't. The
> loss is real too: an action consistent with an attacker-supplied user turn passes all our
> gates. It's the first construction item in our future work plan, and the open design question
> is whether the comparator should itself use a model.

**Q: "Your results are from three runs. Isn't that too few?"**
> Yes, and we say so in the report. Some standard deviations exceed ±0.5. What's robust across
> all three runs is the utility side — benign pass rate 0.94, 1.00 on seven of ten tools, no
> degenerate policy anywhere. The security numbers show the mechanism works but don't quantify
> the protection level. Five seeded runs is the first item in our plan and needs no new code.

**Q: "Have you compared against existing defenses like spotlighting?"**
> The harness is built — five prompt-level defense conditions, same battery, same benign suite
> — but we haven't run it yet. We're deliberately not claiming to beat spotlighting; its own
> paper reports over 50% down to under 2%. Our defensible claim is independence from model
> compliance, and that comparison is scheduled in week 2.

**Q: "Does this run real commands during testing?"**
> No. Tool execution in the evaluation agent is simulated with canned results, so no adversarial
> prompt ever touches a real filesystem or network. That's a deliberate fidelity trade — the same
> one ToolEmu makes explicit.

**Q: "How much does it cost to run?"**
> About ₹786 for the full fifty-run protocol on an owned GPU, ₹4,756 on hosted APIs, ₹1,612 for
> the hybrid we recommend. The generation model choice dominates the bill, not the run count —
> and the agent under test is itself an LLM, accounting for about 56% of all model calls, which
> is the line most budgets miss.

**Q: "Who did what on this project?"**
> `[VERIFY: Aarav — answer from the contribution basis. Note that all repository commits carry a
> single author, so if the panel checks git history it will not show a five-way split. Have an
> explanation ready.]`
