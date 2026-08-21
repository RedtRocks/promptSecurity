# DESIGN SPECIFICATIONS

## 4.1 System Architecture

SecureAgent is organised as five layers with strictly one-directional dependencies: no
lower layer imports from a higher one, and every inter-stage payload crosses a boundary as
a validated data contract rather than an untyped dictionary. Figure 4.1 shows the layering.

```mermaid
flowchart TD
    subgraph L5["Layer 5 — Interface"]
        CLI["Typer CLI<br/>analyze · harden · gateway"]
        GWS["FastAPI gateway server"]
        RPT["Report writer<br/>JSON + HTML"]
        MON["Rich live monitor"]
    end
    subgraph L4["Layer 4 — Orchestration"]
        HARD["Hardening loop<br/>multi-round"]
        PIPE["Single-pass pipeline"]
    end
    subgraph L3["Layer 3 — Stages"]
        S1["Stage 1 — Red Agent<br/>profiler · attacker · grader · refiner"]
        S2["Stage 2 — Defender, analysis<br/>analyzer · synthesizer · editor"]
        S3["Stage 3 — Defender, synthesis<br/>annotator · policy builder"]
    end
    subgraph L2["Layer 2 — Verification"]
        REP["Four-gate replay engine"]
        COV["Coverage aggregator"]
        UTIL["Security/utility evaluator"]
        ENF["Enforcement wrapper"]
    end
    subgraph L1["Layer 1 — Shared foundation"]
        SCH["Pydantic schemas"]
        LLM["LLM provider"]
        AC["Agent client"]
        SET["Settings"]
        MAN["Run manifest"]
    end
    L5 --> L4
    L4 --> L3
    L3 --> L2
    L3 --> L1
    L2 --> L1
    L5 --> L2
```

**FIGURE 4.1: Layered system architecture. Dependencies flow downward only; the shared
foundation has no knowledge of the stages that consume it.**

Two design decisions visible in Figure 4.1 deserve explanation. First, the **verification
layer sits below the stages, not beside them**, because policy synthesis in Stage 3 calls
the verifier to populate its own coverage figures — the policy carries a measurement of
itself, produced by the same deterministic engine that the evaluation harness uses later.
Second, **the interface layer reaches Layer 2 directly** for the gateway command: enforcing
a stored policy requires the replay engine but none of the generation stages, so a
production deployment loads no attack-generation code at all.

Table 4.1 states each layer's responsibility and the layers it is permitted to depend on.

TABLE 4.1: Architectural layers and their responsibilities.

| Layer | Responsibility | Key modules | May depend on |
|---|---|---|---|
| 5 — Interface | Command dispatch, HTTP surface, human-readable output | `cli.py`, `gateway_server.py`, `output/` | 4, 2 |
| 4 — Orchestration | Multi-round control flow, feedback application, stopping criteria | `hardening.py` | 3 |
| 3 — Stages | Attack generation, exploit analysis, policy synthesis | `stage1/`, `stage2/`, `stage3/` | 2, 1 |
| 2 — Verification | Deterministic replay, coverage, security/utility metrics, enforcement | `verifier/` | 1 |
| 1 — Shared foundation | Data contracts, model access, agent transport, configuration | `shared/` | — |

The technology stack sits on this layering as follows: Python 3.10+ throughout; Pydantic v2
for every Layer 1 contract; LiteLLM plus direct HTTP for model access; httpx for agent
transport; FastAPI and uvicorn for both HTTP servers; Typer and Rich for the terminal
interface; and Jinja2 with Chart.js for reporting. There is no database, no message queue
and no build step for the frontend — the HTML report is a single self-contained file.

## 4.2 Design Level Diagrams

### 4.2.1 Use case diagram

```mermaid
flowchart LR
    SEC(["Security Reviewer"])
    DEV(["Integrator / Developer"])
    OPS(["Platform Operator"])
    AGENT(["Target LLM Agent<br/>«external system»"])
    PROV(["LLM Provider<br/>«external system»"])

    UC1["Analyse a tool<br/>for exploitability"]
    UC2["Detect a poisoned<br/>tool description"]
    UC3["Synthesise a<br/>security policy"]
    UC4["Verify policy coverage<br/>and utility"]
    UC5["Harden a tool<br/>iteratively"]
    UC6["Deploy the<br/>policy gateway"]
    UC7["Inspect the<br/>security dashboard"]
    UC8["Audit enforcement<br/>decisions"]

    SEC --> UC1
    SEC --> UC2
    SEC --> UC4
    SEC --> UC7
    DEV --> UC1
    DEV --> UC3
    DEV --> UC5
    OPS --> UC6
    OPS --> UC8
    OPS --> UC7

    UC1 -.->|"«include»"| UC2
    UC3 -.->|"«include»"| UC4
    UC5 -.->|"«include»"| UC1
    UC5 -.->|"«include»"| UC3
    UC6 -.->|"«include»"| UC8

    UC1 --> AGENT
    UC1 --> PROV
    UC3 --> PROV
    UC6 --> AGENT
```

**FIGURE 4.2: Use case diagram. Three human actors and two external systems interact with
eight use cases; dashed arrows denote «include» relationships.**

Figure 4.2 separates three actors whose needs differ materially. The **Security Reviewer**
consumes evidence — they run an analysis, read the poisoning verdict, and inspect coverage
and utility figures, but never deploy anything. The **Integrator** is iterative: they
harden a tool across rounds, which by inclusion requires both analysis and synthesis on
every round. The **Platform Operator** touches only the runtime path — deploying the
gateway and auditing its decisions — and notably never invokes attack generation, which is
why the deployment surface excludes Stage 1 entirely. The two external systems are drawn
explicitly because both are outside the trust boundary and both are the project's principal
cost drivers.

### 4.2.2 Class diagram

```mermaid
classDiagram
    class MCPToolDefinition {
        +str name
        +str description
        +list~MCPParameter~ parameters
        +dict input_schema
        +str kb_context
        +from_mcp_json()
    }
    class ToolProfile {
        +str tool_name
        +list~DataEndpoint~ data_sources
        +list~DataEndpoint~ data_destinations
        +CapabilityProfile capabilities
        +list~str~ injected_instructions
        +bool poisoning_suspected
    }
    class AdversarialPrompt {
        +ToolMisuseCategory misuse_category
        +AttackIntensity attack_intensity
        +str prompt_text
        +str attack_strategy
        +bool is_fallback
        +list~InjectedContent~ injections
    }
    class AgentTrajectory {
        +str prompt
        +list~ToolCall~ tool_calls
        +bool refusal_detected
        +bool ingested_untrusted_content
        +int steps_used
    }
    class ToolCall {
        +str tool_name
        +dict parameters
        +Any response
        +bool success
        +bool untrusted_content
    }
    class AttackRecord {
        +str record_id
        +float final_score
        +bool refusal_occurred
        +str delivery_channel
        +list~AttackIteration~ attack_trajectory
        +list~float~ seed_scores
    }
    class VulnerabilityFinding {
        +str attack_record_id
        +ExploitType exploit_type
        +str exploited_element
    }
    class SAMOSPolicy {
        +str tool_name
        +ConfidentialityAnnotations confidentiality
        +CapabilityAnnotations capabilities
        +SessionTaintRules taint_rules
        +list~EnforcementRule~ enforcement_rules
        +PolicyCoverage policy_coverage
    }
    class EnforcementRule {
        +str rule_id
        +str trigger_condition
        +EnforcementAction action
        +str reason
    }
    class VerifierVerdict {
        +str record_id
        +VerifierVerdictStatus final_status
        +list~str~ triggered_rule_ids
        +bool taint_violation
        +bool integrity_violation
        +int first_blocking_step
    }
    class SecurityUtilityReport {
        +float attack_block_rate
        +float benign_pass_rate
        +float over_block_rate
        +float utility_security_f1
        +bool degenerate_deny_all
    }

    MCPToolDefinition --> ToolProfile : profiled into
    ToolProfile --> AdversarialPrompt : informs
    AdversarialPrompt --> AgentTrajectory : dispatched, produces
    AgentTrajectory *-- ToolCall : contains
    AgentTrajectory --> AttackRecord : aggregated into
    AttackRecord --> VulnerabilityFinding : classified into
    VulnerabilityFinding --> SAMOSPolicy : synthesised into
    SAMOSPolicy *-- EnforcementRule : contains
    AttackRecord --> VerifierVerdict : replayed into
    SAMOSPolicy --> VerifierVerdict : evaluated by
    VerifierVerdict --> SecurityUtilityReport : aggregated into
```

**FIGURE 4.3: Class diagram of the core data contracts, showing the transformation chain
from a tool definition through to the security/utility report.**

Figure 4.3 makes the pipeline's central property visible: it is a **linear transformation
chain with no cycles**, and every arrow is a validated conversion. A tool definition becomes
a profile, which informs adversarial prompts, which produce trajectories, which aggregate
into records, which classify into findings, which synthesise into a policy — and the policy
is then evaluated back against the records it came from. That final loop is the verification
step, and because it consumes the same records rather than fresh ones, coverage is measured
on exactly the attacks the run observed.

Table 4.2 lists the contracts with their roles.

TABLE 4.2: Core data contracts and their stage boundaries.

| Contract | Produced by | Consumed by | Purpose |
|---|---|---|---|
| `MCPToolDefinition` | YAML/JSON parser | Stage 1 | Input tool specification |
| `ToolProfile` | Stage 1.1 profiler | Stage 1.2, Stage 3 | Capability and data-flow characterisation, poisoning verdict |
| `AdversarialPrompt` | Stage 1.2 attacker | Stage 1.3 refiner | One attack, one objective, one technique |
| `AgentTrajectory` | Agent client | Grader, verifier | What the agent actually did |
| `AttackRecord` | Stage 1.3 refiner | Stages 2, 3, verifier | Outcome of one full attack cycle |
| `VulnerabilityFinding` | Stage 2.1 analyzer | Stage 2.3, Stage 3 | Why an attack worked |
| `SAMOSPolicy` | Stage 3.2 policy builder | Verifier, gateway | The enforceable artifact |
| `VerifierVerdict` | Replay engine | Coverage, utility | Deterministic per-record judgement |
| `SecurityUtilityReport` | Utility evaluator | Report writer | Headline metrics |

### 4.2.3 Sequence diagram — attack and refinement cycle

```mermaid
sequenceDiagram
    participant R as Refiner
    participant A as Attacker
    participant AC as Agent Client
    participant AG as Target Agent
    participant G as Grader
    participant L as LLM Provider

    R->>A: request prompt (objective, technique)
    A->>L: generate attack JSON
    L-->>A: attack specification
    A-->>R: AdversarialPrompt (P0)

    loop until success, double refusal, or budget exhausted
        R->>AC: dispatch(prompt, injections)
        AC->>AG: POST /run
        AG->>AG: bounded ReAct loop<br/>(plan, act, observe)
        AG-->>AC: trajectory
        AC-->>R: AgentTrajectory
        R->>G: grade(trajectory, criteria)
        G->>L: judge against rubric
        L-->>G: score
        G-->>R: max(llm_score, heuristic)
        alt score > threshold
            R->>R: mark success, exit
        else agent refused
            R->>R: next_escalation(strategy)
            R->>L: rewrite with stronger technique
            L-->>R: refined prompt
        else failed without refusal
            R->>L: diagnose and rewrite
            L-->>R: refined prompt
        end
    end
    R-->>R: emit AttackRecord
```

**FIGURE 4.4: Sequence diagram of one attack cycle, showing the three-way branch that
distinguishes success, refusal-driven escalation, and diagnostic refinement.**

The branch structure in Figure 4.4 is the mechanism that turns a single prompt into a
search. A refusal is not a terminal failure — it triggers `next_escalation`, which selects
a strictly stronger technique from the ladder. A non-refusal failure triggers diagnostic
rewriting instead, since the agent was willing but the attack was ineffective. Conflating
these two cases would waste budget: rewording a prompt the agent refused on principle
rarely succeeds, whereas escalating past a mere capability gap rarely helps. Listing 4.1
shows the escalation selector.

```python
def next_escalation(current_key: str, intensity: AttackIntensity) -> AttackStrategy | None:
    """Return the next stronger strategy after `current_key` (for refusal escalation)."""
    max_rank = _INTENSITY_MAX_RANK.get(intensity, 7)
    current = _BY_KEY.get(current_key)
    current_rank = current.rank if current else -1
    stronger = [s for s in _ALL if current_rank < s.rank <= max_rank]
    return stronger[0] if stronger else None
```

**LISTING 4.1:** `src/agent_hardener/stage1/attack_strategies.py` — refusal escalation
selects the next strategy strictly above the current rank, capped by the configured
intensity tier.

### 4.2.4 Activity diagram — four-gate policy verification

```mermaid
flowchart TD
    ST(["Start replay"]) --> INIT["Set session taint to<br/>policy initial taint;<br/>integrity_tainted = false"]
    INIT --> NEXT{"More tool calls?"}
    NEXT -->|"no"| FIN["Determine final status<br/>from fired rules"]
    NEXT -->|"yes"| G1{"Gate 1:<br/>capability denied?"}
    G1 -->|"yes"| BLK["Status = BLOCKED<br/>record blocking step"]
    G1 -->|"no"| G2{"Gate 2 (IFC-001):<br/>taint HIGH and<br/>call is a low sink?"}
    G2 -->|"yes"| BLK
    G2 -->|"no"| G2B{"Gate 2b (IFC-002):<br/>integrity tainted and<br/>call is a low sink?"}
    G2B -->|"yes"| BLK
    G2B -->|"no"| G3{"Gate 3:<br/>enforcement rule matches<br/>name AND arguments?"}
    G3 -->|"BLOCK"| BLK
    G3 -->|"AUDIT / CONFIRM"| REC["Record rule;<br/>continue replay"]
    G3 -->|"no match"| UPD
    REC --> UPD["Update taint:<br/>high read upgrades session;<br/>untrusted response sets<br/>integrity_tainted"]
    UPD --> NEXT
    BLK --> END(["Return verdict"])
    FIN --> END
```

**FIGURE 4.5: Activity diagram of the four-gate verification process. The first gate to
block terminates the trajectory; audit and confirmation rules are recorded without halting
replay.**

Two properties of Figure 4.5 are structural guarantees rather than implementation details.
First, **taint is updated after the gates, not before**, so both taint gates test only
taint accumulated from *prior* calls — a tool can never block itself on first use, which
would otherwise make any high-confidentiality reader unusable. Second, **benign
trajectories never carry attacker-controlled content**, so Gate 2b cannot fire on
legitimate use; it raises the attack block rate at zero benign-pass-rate cost. Listing 4.2
shows that gate.

```python
if (
    policy.session_taint_rules.untrusted_input_taints_session
    and integrity_tainted
    and _tool_writes_low_confidentiality(call.tool_name, policy)
):
    verdict.integrity_violation = True
    verdict.triggered_rule_ids.append("IFC-002-UNTRUSTED-TO-ACTION")
    verdict.first_blocking_step = step_idx
    verdict.final_status = VerifierVerdictStatus.BLOCKED
    verdict.notes.append(
        f"Step {step_idx} ({call.tool_name}) blocked by IFC-002: session had "
        "ingested attacker-controlled tool output, then attempted a "
        "consequential action (indirect prompt injection)."
    )
    return verdict
```

**LISTING 4.2:** `src/agent_hardener/verifier/replay.py` — the integrity gate. Note that it
is conditioned on a policy field rather than hardcoded, so the gate enforces a policy
statement rather than a belief baked into the verifier.

### 4.2.5 Entity-relationship diagram — artifact data model

The system has **no database**. All state is in-process plus JSON and YAML artifacts on
disk. Figure 4.6 therefore models the persisted artifacts and their relationships, which is
the meaningful analogue of an ER diagram for this architecture.

```mermaid
erDiagram
    TOOL_DEFINITION ||--|| TOOL_PROFILE : "profiled into"
    TOOL_DEFINITION ||--o{ BENIGN_TASK : "has suite of"
    TOOL_PROFILE ||--o{ ADVERSARIAL_PROMPT : "informs"
    ADVERSARIAL_PROMPT ||--|| ATTACK_RECORD : "resolves to"
    ATTACK_RECORD ||--o{ ATTACK_ITERATION : "contains"
    ATTACK_ITERATION ||--|| AGENT_TRAJECTORY : "captures"
    AGENT_TRAJECTORY ||--o{ TOOL_CALL : "contains"
    ATTACK_RECORD ||--o| VULNERABILITY_FINDING : "classified as"
    VULNERABILITY_FINDING ||--o{ EDIT_RECOMMENDATION : "motivates"
    TOOL_PROFILE ||--|| SAMOS_POLICY : "annotated into"
    SAMOS_POLICY ||--o{ ENFORCEMENT_RULE : "contains"
    SAMOS_POLICY ||--|| DEPLOYMENT_SPEC : "specifies"
    ATTACK_RECORD ||--|| VERIFIER_VERDICT : "replayed into"
    SAMOS_POLICY ||--o{ VERIFIER_VERDICT : "evaluates"
    BENIGN_TASK ||--|| VERIFIER_VERDICT : "replayed into"
    VERIFIER_VERDICT }o--|| SECURITY_UTILITY_REPORT : "aggregated into"
    SAMOS_POLICY ||--|| RUN_MANIFEST : "recorded with"

    TOOL_DEFINITION {
        string name PK
        string description
        json input_schema
        string kb_context
    }
    ATTACK_RECORD {
        string record_id PK
        string tool_targeted FK
        float final_score
        string delivery_channel
        bool refusal_occurred
    }
    SAMOS_POLICY {
        string tool_name PK
        string policy_version
        int generated_from_attack_cycles
    }
    VERIFIER_VERDICT {
        string record_id PK
        string final_status
        bool taint_violation
        bool integrity_violation
        int first_blocking_step
    }
```

**FIGURE 4.6: Entity-relationship model of persisted artifacts. `record_id` and
`tool_name` act as the join keys across artifact files; there is no relational store.**

The cardinalities in Figure 4.6 encode two real constraints. An `ATTACK_RECORD` yields **at
most one** `VULNERABILITY_FINDING`, because analysis is short-circuited for records that did
not succeed — failed attacks produce no finding. And both `ATTACK_RECORD` and `BENIGN_TASK`
produce a `VERIFIER_VERDICT` through the **same** relationship, which is the data-model
expression of the symmetry described in §3.1.4: attacks and benign tasks are judged by
identical machinery.

## 4.3 User Interface Diagrams

SecureAgent has two user-facing surfaces and no graphical application. Both are described
here; neither has been captured as a screenshot yet, since the repository contains no image
files.

### 4.3.1 Terminal interface

```mermaid
flowchart TD
    subgraph TERM["Terminal — analyze run"]
        H["Header: tool name · models · threshold"]
        T["Live attack table"]
        R1["objective · strategy · attempt · score · status"]
        R2["data_exfiltration · authority_pretext · 3/6 · 0.82 · RUNNING"]
        R3["injection_hijack · injected_instruction · 2/6 · 0.95 · SUCCESS"]
        R4["destructive_action · obfuscation · 6/6 · 0.10 · REFUSED"]
        S["Stage progress: 1 attack · 2 analyse · 3 policy"]
        F["Summary: ASR · policy coverage · ABR/BPR/F1"]
    end
    H --> T --> R1 --> R2 --> R3 --> R4 --> S --> F
```

**FIGURE 4.7: Terminal interface layout during an analysis run. The live table is redrawn
from refiner progress events as each attack advances.**

Figure 4.7 shows the information the operator needs while a run is in flight: which
objective and technique each attack is using, how much of its refinement budget is spent,
its current score, and whether it has succeeded, been refused, or is still running. Status
glyphs are selected for compatibility with legacy Windows code pages so the table does not
corrupt on a default terminal.

`[SCREENSHOT: terminal during "agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml", captured mid-run with the Rich live table showing at least three attacks in distinct states — one SUCCESS, one REFUSED, one RUNNING with a partial score. Full window, monospace, dark background. Target filename: fig_4_7_terminal_live.png]`

### 4.3.2 HTML report dashboard

```mermaid
flowchart TD
    subgraph PAGE["report.html — single self-contained page"]
        A["Header: tool · models · run timestamp"]
        B["Headline metrics<br/>ASR · policy coverage · with bootstrap CIs"]
        C["Stage 1 panel<br/>attacks per objective · success by technique"]
        D["Stage 2 panel<br/>exploit type distribution A–E"]
        E["Stage 3 panel<br/>policy summary · capability annotations"]
        F["Security/utility panel<br/>ABR · BPR · F1 · deny-all banner"]
        G["Verifier verdict table<br/>per-record, auditable"]
        H["Attack detail — expandable per record"]
    end
    A --> B --> C --> D --> E --> F --> G --> H
```

**FIGURE 4.8: HTML report dashboard layout. The security/utility panel carries a red banner
when a degenerate deny-all policy is detected.**

The ordering in Figure 4.8 is deliberate: headline metrics first for a reader who wants one
number, then stage-by-stage detail, and finally the per-record verifier verdict table so a
reviewer can audit every coverage figure rather than trusting the aggregate. This dashboard
is the delivered portion of Objective 4b — it presents risk scores, the active policy and
the vulnerability findings, but it is a **static per-run artifact rather than a live
monitoring interface**, and cross-run vulnerability history exists only as aggregated CSV.

`[SCREENSHOT: sample_report/report.html open in a browser, scrolled to show the headline metrics band and the Stage 3 security/utility panel with ABR, BPR and F1 visible together. Target filename: fig_4_8_dashboard.png]`

`[SCREENSHOT: sample_report/report.html scrolled to the per-record verifier verdict table, showing at least four rows with differing final_status values (BLOCKED, AUDITED, UNMITIGATED). Target filename: fig_4_8b_verdicts.png]`

## 4.4 Snapshots of Working Prototype

This section walks through the prototype in the order an operator would exercise it, with
the code that implements each step.

### 4.4.1 Step 1 — Launch the evaluation agent

The target agent is a bounded ReAct loop with simulated tool execution, so adversarial
prompts never perform real filesystem or network operations. It auto-loads every tool in
the corpus, so adding a tool definition requires no server change.

```bash
OLLAMA_BASE_URL=... AGENT_LLM_MODEL=ollama/gemma3:27b AGENT_MAX_STEPS=6 \
  python -m uvicorn scripts.llm_agent_server:app --port 8080
```

`[SCREENSHOT: terminal showing the agent server started, with the uvicorn startup lines and the tool-count log line visible. Target filename: fig_4_9_agent_start.png]`

### 4.4.2 Step 2 — Analyse a tool

```bash
agent-hardener analyze --tool-file mcp_tools/read_file.yaml --config config.yaml
```

Stage 1 profiles the tool, generates attacks across the objective × technique matrix, and
refines each against the live agent. Stage 2 classifies successes. Stage 3 synthesises the
policy — and applies the two guards that prevent a degenerate result. Listing 4.3 is the
capability guard, which exists because unconstrained generation repeatedly disabled the
very capability the tool needs to function.

```python
def _guard_core_capabilities(
    profile: ToolProfile, capabilities: CapabilityAnnotations
) -> None:
    """Prevent a deny-all policy from disabling the tool's core capability."""
    core = {
        "network": profile.capabilities.network,
        "filesystem": profile.capabilities.filesystem,
        "environment": profile.capabilities.environment,
        "execution": profile.capabilities.execution,
    }
    for cap, is_used in core.items():
        if is_used and getattr(capabilities, cap) is False:
            setattr(capabilities, cap, True)
            capabilities.capability_restriction_justifications[cap] = (
                "Kept enabled: disabling would break the tool's core function. "
                "Exfiltration is instead blocked by session taint + enforcement rules."
            )
```

**LISTING 4.3:** `src/agent_hardener/stage3/annotator.py` — the capability guard restores
any capability the profile marks as genuinely used, delegating exfiltration defense to the
taint and enforcement rules, which block the *flow* rather than the *tool*.

### 4.4.3 Step 3 — Measure security against utility

The evaluator replays attack trajectories and benign trajectories through the same gates and
computes the headline metrics. Listing 4.4 shows the arithmetic, including the property that
makes the metric un-gameable.

```python
    n_benign = len(utility_results)
    benign_allowed = sum(1 for u in utility_results if u.allowed)
    bpr = (benign_allowed / n_benign) if n_benign else 0.0
    over_block = (1.0 - bpr) if n_benign else 0.0

    # Harmonic mean of ABR and BPR. A deny-all policy has BPR == 0 -> F1 == 0,
    # so it cannot game the metric even though its ABR is 1.0.
    if n_benign and (abr + bpr) > 0:
        f1 = 2 * abr * bpr / (abr + bpr)
    else:
        f1 = 0.0

    degenerate = bool(n_benign) and benign_allowed == 0 and n_successful > 0
```

**LISTING 4.4:** `src/agent_hardener/verifier/utility.py` — the F1 computation and the
degenerate-policy detector. A policy that blocks every benign task is flagged explicitly
rather than being allowed to hide behind a perfect block rate.

`[SCREENSHOT: terminal at the end of an analyze run showing the final summary table with attack success rate, policy coverage, and the ABR / BPR / F1 line. Target filename: fig_4_10_run_summary.png]`

### 4.4.4 Step 4 — Enforce the policy at runtime

```bash
agent-hardener gateway --policy hardener_output/read_file/report.json \
  --agent-endpoint http://localhost:8080 \
  --host 127.0.0.1 --port 8090 \
  --audit-log hardener_output/gateway_audit.jsonl
```

Figure 4.9 shows the request path.

```mermaid
sequenceDiagram
    participant C as Caller
    participant GW as Policy Gateway
    participant AG as Inner Agent
    participant AUD as Audit sink

    C->>GW: POST /run {prompt}
    GW->>AG: POST /run (forwarded)
    AG-->>GW: full trajectory
    GW->>GW: replay through gates 1–3
    alt a gate blocks
        GW->>GW: rewrite blocked call as failed<br/>drop subsequent calls<br/>set refusal_detected
    end
    GW->>AUD: append audit event
    GW-->>C: trajectory + enforcement_log
```

**FIGURE 4.9: Gateway request path. Enforcement is post-hoc — the inner agent completes its
trajectory, which the gateway then replays and truncates at the first blocked call.**

The post-hoc design in Figure 4.9 is an honest limitation rather than a subtlety: the
gateway prevents the *observable effect* of a blocked call being returned to the caller, but
does not prevent the inner agent from having attempted it. A pre-dispatch interception design
would be strictly stronger and is recorded in §5.4.

The endpoints exposed by the running gateway are listed in Table 4.3.

TABLE 4.3: Gateway API surface.

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `/run` | `{prompt}` | Trajectory + `enforcement_log` + `policy_tool`; 400 on invalid body, 502 on inner-agent error |
| GET | `/health` | — | Status, policy tool, rule and taint-rule counts, initial taint |
| GET | `/policy` | — | The full policy document |
| GET | `/audit` | `?limit=N` | Recent enforcement events from the audit ring |
| POST | `/tools/list` | JSON-RPC | The policy's tool annotations |

`[SCREENSHOT: two terminals side by side — left running the gateway with its startup banner, right showing a curl POST to /run whose JSON response contains a non-empty enforcement_log. Target filename: fig_4_11_gateway_block.png]`

`[SCREENSHOT: browser or curl output of GET /audit showing at least two audit events, one with "blocked": true. Target filename: fig_4_12_audit.png]`

### 4.4.5 Step 5 — Tool-poisoning detection

The corpus includes seven poisoned tool descriptions across seven payload families, each
paired with a matched clean control so that a detector which flags everything scores no
better than chance on precision.

```bash
python scripts/tool_poisoning_eval.py --config config.yaml --repeats 3 --out poisoning_eval.json
```

**This experiment has not yet been executed.** The script is complete and the corpus is in
place, but no recall, false-positive-rate or precision figures exist. It is scheduled first
in §5.4 alongside the adaptive-attack evaluation.

### 4.4.6 What the prototype does not demonstrate

Three capabilities described in the approved objectives are not demonstrable in the current
prototype, and no step above should be read as evidence for them. There is **no Intent
Alignment Layer** — no step performs semantic goal-versus-action comparison. There is **no
live security dashboard** — the HTML report is generated per run and read offline, and the
gateway's audit endpoint returns JSON with no interface. And **no measured risk-reduction
figure** exists, because the adaptive-attack evaluation that would produce it has never been
run.
