# SECUREAGENT

## Adversarial Attack Surface Analysis and Runtime Policy Enforcement for AI Agent Tools

Capstone Project Report — Mid Semester Evaluation

Submitted by:
(102303179) AARAV DUDEJA
(102303904) AKSHAT SRIVASTAVA
(102306026) HITEN YADAV
(102317215) SANIL GROVER
(102306046) SIMRAN ARORA

BE Fourth Year, COE/CSE — CPG No: 215

Under the Mentorship of
**Dr. Gurpal Singh Chhabra**, Assistant Professor, CSE
**Dr. Amit Kumar Trivedi**, Assistant Professor, CSE

Computer Science and Engineering Department
Thapar Institute of Engineering and Technology, Patiala
August 2026

---

# ABSTRACT

Large language model agents now act on the world through tools: they read files, query
databases, send email and run commands. The Model Context Protocol (MCP) has made these
tools shareable between organisations, which creates a security boundary that current
practice does not defend. When an agent connects to a third-party tool server, the tool's
description is written by that third party but is read by the agent as trusted instruction
text, and any content the tool returns can carry instructions the agent will follow.

SecureAgent addresses this boundary without modifying the agent or the tool. Given only a
tool's public description, the system generates adversarial prompts across six categories
of tool misuse, runs them against a live agent, and records what the agent actually did.
From the attacks that succeeded it synthesises an information-flow security policy, and it
enforces that policy at runtime through a gateway placed in front of the agent.

The central design problem is that blocking attacks is trivial if utility is ignored: a
policy that disables the tool blocks every attack and every legitimate use. SecureAgent
therefore measures both sides, replaying attack traces and legitimate-use traces through
the same enforcement gates. Across a ten-tool corpus, the synthesised policies blocked 80%
of the attacks that had succeeded against the unguarded agent while allowing 100% of
legitimate use. Live enforcement was demonstrated end to end: an attempt to read a secret
file and email it out was blocked at the network step, while an ordinary file read through
the same gateway completed normally.

Four objectives were approved at proposal evaluation. Three are substantially complete and
one is partial, giving 71% weighted completion at mid-semester. The principal outstanding
items are statistical repetition of the corpus evaluation and calibration of the automated
grader against human labels.

**Keywords:** AI agent security, Model Context Protocol, prompt injection,
information-flow control, runtime policy enforcement.

---

# CHAPTER 1: INTRODUCTION

## 1.1 Project Overview

An AI agent is a language model that has been given tools and permission to use them. The
model receives a request, decides which tools to call, sees the results, and continues until
it judges the task complete. This is a significant change from a chatbot: the model's output
is no longer text that a human reads and evaluates, it is an action that takes effect.

The Model Context Protocol standardised how tools are described and offered to agents. A
tool server publishes each tool's name, a natural-language description of what it does, and
a schema for its parameters. An agent connects, reads the list, and can immediately use the
tools. The benefit is obvious — tools become portable across vendors — but so is the
consequence. The description that tells the agent what a tool does is supplied by whoever
runs the server, and the agent treats it as trustworthy. When that server belongs to someone
else, an untrusted party is writing text directly into the agent's reasoning.

Two attack channels follow. In the first, the attacker controls the tool description and
plants instructions inside it, so the agent is misdirected before any tool runs; OWASP
catalogues this as tool poisoning [20]. In the second, the description is honest but the
data the tool returns contains instructions — a web page, an email, a database row — and the
agent, unable to separate data from instruction, follows them. This is indirect prompt
injection [5], and it is the harder case because the user's own request was entirely benign.

Existing defences fall into two groups, and neither closes the gap. Prompt-level defences
such as spotlighting [11] mark untrusted content so the model is likelier to ignore embedded
instructions. They are cheap and helpful, but they work by persuading the model, so they
fail exactly when the model has been successfully manipulated. Architectural defences such
as CaMeL [17] give strong guarantees by restructuring the agent around a trusted planner,
but they require rebuilding the agent, which is not an option for a team that merely
connects to a third-party tool.

SecureAgent occupies the space between them. It assumes the agent cannot be rewritten and
the tool's implementation cannot be inspected — only its public description is available,
which is precisely the position of an organisation adopting an external tool server. From
that description alone it determines how the tool can be abused, and it produces a policy
enforced outside the model, so enforcement does not depend on the model behaving.

The system runs in three stages. The first profiles the tool, generates adversarial prompts
across six misuse categories using eight named red-team techniques, sends them to a live
agent, and scores what the agent did. Attacks that fail are refined and retried with
progressively stronger techniques. The second stage analyses the successful attacks,
classifies why each worked, and aggregates patterns across them. The third converts those
patterns into a machine-readable policy: which capabilities the tool may use, how sensitive
data may flow, and which operations must be blocked, audited, or escalated for human
confirmation.

The policy is then checked rather than assumed. Every recorded attack trace is replayed
through the policy by a deterministic checker that consults no language model, so reported
effectiveness is a measurement rather than a prediction. The same checker replays a suite of
legitimate tasks, which is what stops the security number being achieved by simply switching
the tool off. Finally a gateway loads the policy and enforces it on a live agent, so the
offline measurement is reproduced in a running system.

## 1.2 Need Analysis

Tool-using agents are being deployed faster than they are being secured. Organisations are
connecting agents to email, file storage, internal databases and shell access, and MCP has
removed most of the friction from doing so with third-party tools. The security assumption
inherited from ordinary software — that a component's description is documentation, not
input — does not hold when the consumer of that description is a language model.

The practical gap is that the party adopting a tool is usually not the party that wrote it,
and has neither the source code nor the ability to change the agent framework. Existing work
does not serve this position. Benchmarks such as AgentDojo [8] and AgentHarm [9] measure how
often attacks succeed but produce no defence. Architectural defences produce a strong defence
but require control of the agent. Prompt-level defences require neither, but are only as
reliable as the model's compliance.

There is also a workload argument. Writing a sound information-flow policy by hand demands
security expertise most teams lack, must be repeated per tool, and goes stale whenever a tool
changes. Automating policy generation from the description is what makes the approach usable
at the scale at which tools are actually being adopted.

The significance of the work is therefore that it targets the common deployment position
rather than the ideal one, and that it produces an artefact — an enforceable policy — rather
than only a measurement.

## 1.3 Research Gaps

**Gap 1 — Evaluation without defence.** Agent security benchmarks quantify attack success
and stop there. AgentDojo [8] and AgentHarm [9] provide attack suites and scoring; neither
emits a policy or any runtime control. The step from "this tool is exploitable" to "here is
what to enforce" is left to the practitioner.

**Gap 2 — Defences that require rewriting the agent.** CaMeL [17] and related design
patterns [16] achieve strong guarantees by restructuring the agent so untrusted data cannot
influence control flow. This is sound but assumes ownership of the agent. No comparable
protection exists for a team that only connects to a third-party tool.

**Gap 3 — Defences that depend on model compliance.** Spotlighting and instruction defence
[11] reduce injection success substantially, but they operate by persuading the model. A
model that has been jailbroken ignores them, which is exactly the condition under which a
defence is needed. Enforcement independent of the model's cooperation is not addressed.

**Gap 4 — Security measured without utility.** Attack-block rate alone is trivially gamed,
since denying a capability blocks every attack. Published defence results frequently omit the
false-positive rate against legitimate use, so a good policy cannot be distinguished from a
merely restrictive one. Where the trade-off is discussed [18], [19], it is not reported as a
paired metric.

**Gap 5 — The tool description as an untrusted input.** Prompt injection research
concentrates on the user turn and on retrieved content [5], [6]. In the third-party case the
description itself is attacker-supplied, and OWASP lists tool poisoning as a distinct MCP
risk [20], but automated detection evaluated against matched clean controls is largely
absent, so reported detection rates cannot be separated from a strategy of flagging
everything.

## 1.4 Problem Definition and Scope

**Problem.** Given only the public description of an MCP tool and access to a running agent
that uses it, automatically determine how that tool can be abused and produce a policy that
prevents the abuse at runtime without materially reducing the tool's legitimate usefulness.

**In scope.** Third-party tool descriptions treated as untrusted; indirect prompt injection
delivered through tool results; automatic synthesis of information-flow policies; runtime
enforcement in front of an unmodified agent; and paired measurement of security and utility.

**Out of scope, stated deliberately.** The system does not inspect or modify tool
implementations, so it cannot detect a tool whose description is honest but whose code is
malicious. Cross-server tool shadowing, rug pulls (a server altering a tool after approval),
and MCP authorisation and confused-deputy problems are not addressed. The honest description
of the contribution is attack-surface analysis derived from descriptions, plus runtime policy
synthesis and enforcement.

## 1.5 Assumptions and Constraints

TABLE 1.1: Assumptions and constraints.

| # | Type | Statement | Consequence if false |
|---|---|---|---|
| A1 | Assumption | The tool description available to us is the one the agent is given | Analysis targets a different surface than the agent sees |
| A2 | Assumption | The agent is reachable over a network interface for testing | Attacks cannot be executed against real behaviour |
| A3 | Assumption | Tool execution during testing can be safely simulated | Adversarial prompts would cause real damage |
| A4 | Assumption | A capability can be inferred from a tool's name and schema | Capability gates may mis-classify unusual tools |
| C1 | Constraint | No modification to the agent framework or tool implementation | Rules out architectural defences |
| C2 | Constraint | Enforcement must not depend on the model's cooperation | Rules out prompt-only defences as the primary control |
| C3 | Constraint | Evaluation runs on locally hosted open models | Results are model-specific and must be reported as such |
| C4 | Constraint | Attack generation and grading use different model families | Prevents a model from grading its own output |

## 1.6 Standards

Threat naming follows the OWASP Top 10 for LLM Applications and the OWASP MCP Top 10 [20],
so findings map onto vocabulary a security team already uses. The tool format follows the
Model Context Protocol specification [27]. The policy model applies established
information-flow control principles [15], specifically the rule that data must not flow from
a high-confidentiality source to a low-confidentiality sink. References follow IEEE style.

## 1.7 Approved Objectives

TABLE 1.2: Status against the objectives approved at proposal evaluation.

| Obj | Objective | Status | % |
|---|---|---|---|
| O1 | Red Agent — schema-aware adversarial attack generation | Substantially complete | 85 |
| O2 | Defender Agent — failure analysis and policy synthesis | Substantially complete | 90 |
| O3 | Policy enforcement engine and verification loop | Substantially complete | 80 |
| O4 | Intent alignment layer and security dashboard | Partial | 30 |
| | **Weighted completion** | | **71** |

Two deviations are material and are stated here rather than deferred to Chapter 5. First,
the intent alignment layer proposed under O4 — a semantic comparison of the user's goal
against the agent's actions — was not built. It was superseded by deterministic
information-flow gates, which are stronger where they apply because they do not rely on a
model's judgement, but narrower, because they reason about data flow rather than intent.
Second, the dashboard was delivered as a static per-run report and an audit endpoint rather
than as live monitoring.

## 1.8 Methodology

The project follows a design-science method: build an artefact, then evaluate it against
criteria fixed in advance. Development is iterative, each cycle adding a capability together
with the measurement that demonstrates it. Evaluation is empirical rather than analytical —
attacks are executed against a live agent and outcomes recorded, rather than reasoning about
what a model might do. The paired security-utility metric was fixed before results were
collected, so evaluation could not be tuned toward a favourable number. Chapter 3 gives the
detail.

## 1.9 Project Outcomes and Deliverables

TABLE 1.3: Deliverables at mid-semester.

| # | Deliverable | Objective | Status |
|---|---|---|---|
| 1 | Three-stage analysis pipeline with a command-line interface | O1, O2 | Delivered |
| 2 | Attack generation over six misuse categories and eight techniques | O1 | Delivered |
| 3 | Exploit classification and cross-attack pattern aggregation | O2 | Delivered |
| 4 | Machine-enforceable policy in a structured format | O2 | Delivered |
| 5 | Deterministic policy checker with four enforcement gates | O3 | Delivered |
| 6 | Runtime enforcement gateway with audit trail | O3 | Delivered |
| 7 | Paired security-utility measurement | O3 | Delivered |
| 8 | Ten-tool evaluation corpus with legitimate-use suites | O1, O3 | Delivered |
| 9 | Seven poisoned tool descriptions with matched clean controls | O1 | Delivered |
| 10 | Static security report per run | O4 | Delivered |
| 11 | Grader calibration against human labels | O1, O2 | Outstanding |
| 12 | Repeated runs with error bars | O3 | In progress |

## 1.10 Novelty of Work

The contribution is the combination rather than any single element, and three points are
new in combination.

The system produces a *defence* from a *description*, closing the gap between benchmarks
that only measure and architectural defences that require agent ownership. Enforcement sits
outside the model, so it continues to hold when the model has been manipulated — which is
what distinguishes it from prompt-level mitigation.

Effectiveness is measured, not predicted. Attack traces are replayed through the policy by a
deterministic checker with no model involvement, and the same checker replays legitimate
tasks, so security and utility are reported as a pair. This defeats the degenerate policy
that blocks everything, and the project has direct evidence the safeguard is necessary:
early versions repeatedly generated exactly that policy, because denying a capability is the
bluntest lever available, and two specific guards had to be added to prevent it.

Finally, the tool description is treated as an attack surface in its own right, and poisoned
descriptions are evaluated against matched clean controls, so detection rates cannot be
inflated by a detector that simply flags everything.

---

# CHAPTER 2: REQUIREMENT ANALYSIS

## 2.1 Literature Survey

### 2.1.1 Theory Associated With the Problem Area

Two bodies of theory meet in this project.

The first is prompt injection. Language models process instructions and data in the same
channel, so text that arrives as data can be interpreted as instruction. Direct injection
arrives in the user's own message [1], [4]. Indirect injection arrives through content the
model retrieves [5], and is more dangerous in an agent because the user's request may be
entirely innocent while the retrieved content carries the attack. Attack strength has
improved steadily, from hand-written jailbreaks to automated and transferable methods
[2], [3], [25].

The second is information-flow control, a decades-old discipline in systems security [15].
Data is labelled with a confidentiality level and the system prevents flows from high to
low. The classical rule is that once a process has read secret data it may not write to a
public sink. This transfers to agents with one addition: an integrity dual, in which content
that arrived from an untrusted source taints subsequent actions, so an agent that has read
attacker-controlled text may not then take a consequential action. The first rule stops
private data leaving; the second stops attacker instructions being carried out.

### 2.1.2 Existing Systems and Solutions

Benchmarks establish that the problem is real. AgentDojo [8] evaluates agents on realistic
tasks with injected attacks; AgentHarm [9] measures harmful agent behaviour across
categories; InjecAgent [6] targets tool-integrated agents specifically. All measure; none
defend.

Prompt-level defences are the deployed state of practice. Spotlighting [11] marks untrusted
content by transformation or delimiting and reports substantial reductions in injection
success. Instruction defence and sandwiching restate the rules around untrusted content.
All share the limitation that they rely on the model complying.

Architectural defences are the strongest published results. CaMeL [17] separates a
privileged planner from an unprivileged component that touches untrusted data, so injected
instructions cannot alter control flow. Related work generalises this into design patterns
[16]. These are the closest prior art and the project does not claim to beat them on
security; the difference is that they require rewriting the agent and this work does not.

MCP-specific work is newer. OWASP has published an MCP Top 10 [20] naming tool poisoning
explicitly, and surveys of deployed servers report poisoned descriptions in the wild.

### 2.1.3 Research Findings From Existing Literature

TABLE 2.1: Representative literature and what each contributes.

| # | Work | Contribution | Limitation for this project |
|---|---|---|---|
| 1 | Prompt injection formalisation [1] | Names and structures the attack class | No agent or tool context |
| 2 | Automated jailbreak generation [2] | Attacks can be generated, not hand-written | Targets chat, not tool use |
| 3 | Transferable adversarial prompts [3] | Attacks transfer across models | No defence proposed |
| 4 | Universal triggers [4] | Short suffixes subvert behaviour | Pre-agent era |
| 5 | Indirect injection [5] | Retrieved content is an attack channel | Demonstrates risk only |
| 6 | InjecAgent [6] | Benchmarks tool-integrated agents | Measurement only |
| 7 | Multi-step agent attacks [7] | Attacks span several tool calls | No policy output |
| 8 | AgentDojo [8] | Realistic agent benchmark with injections | No defence artefact |
| 9 | AgentHarm [9] | Harmful-behaviour taxonomy | Content harms, not tool misuse |
| 10 | Agent security survey [10] | Consolidates the threat landscape | Survey, not a system |
| 11 | Spotlighting [11] | Practical, effective prompt-level defence | Depends on model compliance |
| 12 | Tool-use safety analysis [12] | Tool schemas shape the attack surface | No enforcement |
| 13 | Agent evaluation methodology [13] | Evaluation design guidance | Not security-specific |
| 14 | Confused deputy analysis [14] | Classical authority-misuse framing | Predates LLM agents |
| 15 | Information-flow control [15] | Formal basis for the policy model | Not written for agents |
| 16 | Agent design patterns [16] | Architectural defence patterns | Requires agent ownership |
| 17 | CaMeL [17] | Strongest published defence | Requires agent rewrite |
| 18 | Security-utility trade-off [18] | Establishes the tension | Not reported as a paired metric |
| 19 | Defence evaluation critique [19] | Shows how defences are over-claimed | Critique, not a system |
| 20 | OWASP MCP Top 10 [20] | Authoritative MCP threat naming | Taxonomy, not tooling |
| 21 | Poisoned-server survey [21] | Poisoning occurs in deployed servers | No matched controls |
| 22 | Agent memory attacks [22] | Persistence as an attack goal | Out of scope here |
| 23 | Guardrail systems [23] | Runtime filtering approaches | Content filters, not data flow |
| 24 | Red-teaming with models [24] | Models can generate attacks at scale | Not tool-specific |
| 25 | Automated jailbreak search [25] | Iterative refinement improves attacks | Chat setting |
| 26 | Web-agent risks [26] | Real-world agent exposure | Domain-specific |
| 27 | MCP specification [27] | Defines the tool contract | Standard, not security |

### 2.1.4 Problem Identified

The literature establishes that tool-using agents are attackable through both the tool
description and the tool result, and that the two viable defence families each fail a
practical requirement: prompt-level defences depend on the model, architectural defences
depend on owning the agent. What is missing is a defence available to the party that adopts
a third-party tool, that does not rely on model compliance, and whose effectiveness is
reported together with its cost to legitimate use.

### 2.1.5 Survey of Tools and Technologies Used

TABLE 2.2: Technologies and rationale.

| Technology | Role | Why chosen |
|---|---|---|
| Python 3.10+ | Implementation language | Ecosystem for LLM tooling and testing |
| Pydantic | Typed data contracts between stages | Validation at every stage boundary; no untyped data crosses |
| LiteLLM | Unified access to multiple model providers | Allows the cross-family grader requirement |
| Locally hosted open models | Attack generation, grading, agent | Cost, reproducibility, no data leaving the machine |
| FastAPI and Uvicorn | Agent server and enforcement gateway | Lightweight async HTTP suited to a proxy |
| pytest | Automated testing | 205 tests, including invariants such as every corpus tool having a legitimate-use suite |
| YAML | Tool and task definitions | Human-editable; matches how MCP tools are distributed |

## 2.2 Software Requirement Specification

### 2.2.1 Introduction

**2.2.1.1 Purpose.** To specify the behaviour of a system that analyses an MCP tool for
exploitability, synthesises a security policy, and enforces that policy at runtime.

**2.2.1.2 Intended Audience.** The evaluation panel and project mentors; security engineers
who would deploy such a gateway; and researchers extending the work. Readers wanting the
threat model should read 1.4 and 2.1.4; readers wanting results should read 4.4 and 5.1.

**2.2.1.3 Project Scope.** Analysis and enforcement for individual MCP tools, in the
deployment position where the agent and the tool implementation are both outside the user's
control.

### 2.2.2 Overall Description

**2.2.2.1 Product Perspective.** The system is a standalone component that sits beside an
existing agent. In analysis mode it acts as a client, sending adversarial prompts and
recording behaviour. In enforcement mode it acts as a proxy between the agent's callers and
the agent, applying the policy to every trajectory before returning it. Neither mode requires
changes to the agent.

**2.2.2.2 Product Features.** Tool profiling from a description; adversarial attack
generation with iterative refinement; automatic policy synthesis; deterministic policy
checking against both attack and legitimate-use traces; runtime enforcement with an audit
trail; and per-run reporting.

### 2.2.3 External Interface Requirements

**2.2.3.1 User Interfaces.** A command-line interface with three commands: analyse a tool,
iteratively harden it, and run the enforcement gateway. Output is a machine-readable report
and a static HTML dashboard showing attack outcomes, policy contents and the
security-utility result.

**2.2.3.2 Hardware Interfaces.** A GPU-equipped host for model inference. Evaluation used a
27-billion-parameter model for attack generation and the agent, and a 30-billion-parameter
model from a different family for grading.

**2.2.3.3 Software Interfaces.** HTTP to the agent under test; HTTP to the model inference
server; tool definitions in MCP format.

### 2.2.4 Other Non-functional Requirements

**2.2.4.1 Performance.** Analysis of one tool completes in roughly 15 to 30 minutes. This is
acceptable because analysis is performed once when a tool is adopted, not per request.
Enforcement adds negligible latency, since the gates are deterministic checks with no model
call.

**2.2.4.2 Safety.** Tool execution during testing is simulated and never performs real file,
network or shell operations, so adversarial prompts cannot cause damage. This is a hard
requirement: the system deliberately generates prompts designed to trigger destructive
actions.

**2.2.4.3 Security.** Enforcement must not depend on the model's cooperation. Attack
generation and grading must use different model families so that no model grades its own
output. Every enforcement decision must be recorded with the gate and rule that produced it,
so decisions are auditable.

## 2.3 Cost Analysis

TABLE 2.3: Project cost.

| Item | Basis | Cost |
|---|---|---|
| Model inference | Locally hosted open-weight models | Nil (no API charges) |
| Compute | Existing GPU hardware | Nil marginal |
| Software | Open-source libraries throughout | Nil |
| Effort | Five members, one semester | Principal cost |

The decision to use locally hosted open models rather than commercial APIs removed the
project's only significant recurring cost. It also improved reproducibility, since model
versions are pinned locally, and avoided sending adversarial prompts to third-party
services.

## 2.4 Risk Analysis

TABLE 2.4: Principal risks and their current status.

| # | Risk | Severity | Mitigation | Status |
|---|---|---|---|---|
| R1 | A model grading its own output inflates results | High | Attack generation and grading use different model families; recorded per run | Resolved |
| R2 | Policies achieve high block rates by disabling the tool | High | Paired security-utility metric; two guards preventing capability denial of the core function | Resolved |
| R3 | Legitimate-use suites written by the same authors as the expected calls | High | Suites re-recorded from the live agent, provenance recorded | Resolved |
| R4 | Automated grader disagrees with human judgement | High | Blind labelling set prepared and balanced across categories | Open — labels not yet collected |
| R5 | Single-run results quoted as if stable | High | Repeated runs in progress; results reported as one run until complete | Open |
| R6 | Capability inferred from tool names may mis-classify | Medium | Deliberate over-approximation, so reported blocking is a lower bound | Accepted |
| R7 | Policies reason only about the tool they were generated for | Medium | Documented limitation; cross-tool flow is future work | Accepted |
| R8 | No continuous integration, so regressions surface late | Medium | Tests run manually before each milestone | Open |

---

# CHAPTER 3: METHODOLOGY ADOPTED

## 3.1 Investigative Techniques

The project needed to answer two different kinds of question, and they demanded different
methods.

The first question is empirical: *can this tool be abused, and how?* This cannot be settled
by inspection, because whether an attack succeeds depends on how a particular model responds
to a particular phrasing. The chosen technique is therefore adversarial experimentation.
Attacks are generated, executed against a live agent, and the agent's actual behaviour is
recorded. A model then grades each trajectory against criteria fixed when the attack was
created.

Two safeguards were necessary to keep this honest. Grading and generation use models from
different families, because a model asked to grade its own output is not an independent
judge. Tool execution is simulated, because the system deliberately generates prompts
intended to cause destructive actions, and a genuine execution path would make the
experiment dangerous.

The second question is analytical: *does the generated policy actually stop these attacks?*
Here experimentation would be the wrong instrument. Asking a model whether a policy blocks a
trace reintroduces exactly the subjectivity the policy is meant to remove. The technique
chosen is deterministic replay: each recorded trace is walked through the policy's gates by
ordinary code, with no model consulted. The outcome is reproducible and auditable, and every
decision can be traced to the rule that caused it.

A third technique was required by a problem specific to security evaluation. A defence can
always be made to look good by measuring only what it blocks. The project therefore fixed a
paired metric before collecting results: the fraction of successful attacks blocked, and the
fraction of legitimate tasks still permitted, combined into a harmonic mean so that a policy
scoring perfectly on one and zero on the other is scored as worthless. Critically, both
figures are produced by the *same* replay engine over the same gates, so the comparison
cannot be biased by measuring the two sides differently.

This decision proved to be load-bearing rather than ceremonial. Early versions of the system
frequently produced policies that disabled the tool's core capability — a file reader whose
policy forbade file access. Such a policy blocks every attack. Without the utility half of
the metric, those runs would have been recorded as complete successes. Two specific guards
were added: one preventing the removal of a capability the tool is documented to need, and
one that downgrades a blanket block on the tool's own primary operation to a
human-confirmation requirement. Both were needed; a live run with only the first still
produced a degenerate policy.

TABLE 3.1: Techniques and rationale.

| Question | Technique | Why not the alternative |
|---|---|---|
| Is the tool exploitable? | Adversarial experimentation against a live agent | Static inspection cannot predict model behaviour |
| Does the policy block the attacks? | Deterministic replay through the gates | A model judge reintroduces subjectivity |
| Does the policy preserve utility? | Same replay over legitimate-use traces | Measuring only security rewards deny-all policies |
| Are legitimate-use traces realistic? | Recorded from the live agent | Hand-written traces are circular |

## 3.2 Proposed Solution

The solution is a pipeline of three stages followed by enforcement.

**Stage 1 — attack.** The tool description and parameter schema are profiled to identify the
tool's domain, its capabilities, and any ambiguity in its documentation that an attacker
could exploit. Adversarial prompts are then generated across six categories of tool misuse:
data exfiltration, destructive action, unauthorised communication, capability escalation,
persistence tampering, and injection hijack. These categories were chosen deliberately over
a content-harm taxonomy, because asking a file-reading tool to produce hate speech is
incoherent and fails for reasons that say nothing about the tool's security.

Each attack uses a named red-team technique — direct request, benign decomposition,
authority pretext, hypothetical framing, tool chaining, context priming, obfuscation, and
strong authority override — ordered by strength. When the agent refuses, the attack is not
merely reworded; it is regenerated using a stronger technique. This escalation is what
distinguishes the approach from single-shot attack generation.

The injection hijack category is different in kind and is kept separate throughout. Its
payload is planted in a tool *result* rather than the user's message, and the user's request
is benign. Mixing these results with direct attacks would obscure the distinction between an
agent that obeys a malicious user and one that is hijacked while serving an honest one, so
the two are never pooled.

**Stage 2 — analysis.** Successful attacks are classified by why they worked, and patterns
are aggregated across them to identify the primary exploit vector for the tool. The stage
also proposes changes to the tool's own documentation to remove the ambiguities the attacks
exploited.

**Stage 3 — policy synthesis.** The patterns become a structured policy with four parts:
confidentiality labels for what the tool reads and writes; capability annotations for
network, filesystem, environment and execution access; taint rules describing how sensitivity
propagates through a session; and specific enforcement rules with an action of block, audit,
or require confirmation.

**Enforcement.** A gateway loads the policy and sits between callers and the agent. Every
trajectory the agent returns is checked against four gates before being released. The
capability gate rejects a call whose capability the policy denies. The confidentiality gate
maintains a session taint level and blocks a write to a public sink once secret data has
been read, stopping private data leaving. The integrity gate is its dual: once a response
has carried attacker-controlled content, a subsequent consequential action is blocked,
stopping an injection being carried out. Because legitimate traces never carry untrusted
content, this gate raises security at no cost to utility, which is a structural property
rather than an empirical finding. The final gate applies the specific enforcement rules,
matched not only on the tool name but on argument values, so a rule targeting one dangerous
query does not block every query.

## 3.3 Work Breakdown Structure

TABLE 3.2: Work packages and ownership.

| WP | Package | Owner | Status |
|---|---|---|---|
| 1 | Attack generation, techniques, refinement | Aarav Dudeja | Complete |
| 2 | Failure analysis and pattern aggregation | Akshat Srivastava | Complete |
| 3 | Policy synthesis and anti-degeneracy guards | Hiten Yadav | Complete |
| 4 | Deterministic checker and paired metric | Simran Arora | Complete |
| 5 | Enforcement gateway and audit trail | Sanil Grover | Complete |
| 6 | Evaluation corpus and legitimate-use suites | Shared | Complete |
| 7 | Poisoned descriptions and controls | Sanil Grover | Code complete, evaluation pending |
| 8 | Defence baseline comparison | Simran Arora | Code complete, evaluation pending |
| 9 | Grader calibration against human labels | Aarav Dudeja | Labelling set prepared |
| 10 | Repeated runs for error bars | Shared | In progress |

The packages marked pending account for most of the outstanding completion percentage. They
are not blocked by missing design; the code exists and the work required is execution and
analysis time.

## 3.4 Tools and Technology

Implementation is entirely in Python. Data passing between stages is validated by typed
models, so no untyped structure crosses a stage boundary — a deliberate choice, because the
stages are developed by different members and the contract between them is where integration
errors would otherwise accumulate. Model access is routed through a single abstraction so
that changing providers does not touch pipeline code, which is what makes the cross-family
grading requirement practical. The agent under test and the enforcement gateway are both
lightweight HTTP services. Testing uses pytest, with 205 tests covering the stage contracts,
the enforcement gates, and invariants such as every corpus tool having a legitimate-use
suite.

---

# CHAPTER 4: DESIGN SPECIFICATIONS

## 4.1 System Architecture

The system has two operating modes sharing one policy representation.

In **analysis mode**, the tool definition enters the pipeline. Stage 1 attacks the tool
through the live agent and records trajectories. Stage 2 analyses the successes. Stage 3
emits the policy. The deterministic checker then replays both the attack traces and the
legitimate-use traces through that policy and reports the paired metric. Output is a
machine-readable report, an HTML dashboard, and a manifest recording the models, settings and
library versions used, so a run can be reproduced.

In **enforcement mode**, the same policy is loaded by a gateway that sits between the agent's
callers and the agent. Requests pass through; responses are checked against the four gates
before release; every decision is appended to an audit log.

FIGURE 4.1: System architecture — analysis mode produces a policy, enforcement mode applies
it. *[SCREENSHOT: block diagram]*

## 4.2 Design Level Diagrams

The core design decision is that the checker is shared. The same replay engine, over the same
gates, processes adversarial and legitimate traces. This matters because if security and
utility were measured by different code, the comparison could be biased — accidentally or
otherwise — by treating the two cases differently. Sharing the engine makes that structurally
impossible.

The four gates are ordered, and the order is deliberate. Capability denial is checked first
because it is unconditional. The two taint gates follow, and each deliberately tests taint
accumulated from *prior* calls only. Without this, a tool that both reads sensitive data and
is labelled as writing to a public sink would block itself on its very first call, destroying
all legitimate use. Enforcement rules are checked last, since they are the most specific.

Session taint is monotonic: once raised, it does not fall within a session. This is the
conservative choice, and it means the system may over-block rather than under-block, which is
the correct direction for a security control.

FIGURE 4.2: The four enforcement gates in order, with the taint state carried between calls.
*[SCREENSHOT: gate flow diagram]*

## 4.3 User Interface Diagrams

The interface is a command line for operators and an HTML report for review. The report
opens with the headline attack outcomes, then the generated policy in readable form, then the
security-utility result, and finally a per-attack table giving each trace's verdict and the
gate that produced it. That last table is the important one for an evaluator, because it lets
every reported number be audited down to the individual decision rather than taken on trust.

FIGURE 4.3: HTML report, security-utility section. *[SCREENSHOT: report dashboard]*

## 4.4 Snapshots of Working Prototype

**Step 1 — analysis.** Running the analysis command against a file-reading tool profiles the
tool, generates six attacks, executes them against the live agent, and reports how many
succeeded. In the run shown, one of six attacks succeeded at the strict scoring threshold,
and the pipeline proceeded to generate a policy from it.

FIGURE 4.4: Analysis run in progress. *[SCREENSHOT: terminal during analysis]*

**Step 2 — corpus results.** The pipeline was run across all ten tools in the corpus.

TABLE 4.1: Security-utility results, ten-tool corpus, one complete run.

| Tool | Successful attacks | Attacks blocked | Legitimate use allowed | F1 |
|---|---|---|---|---|
| Command execution | 5 of 6 | 0.80 | 1.00 | 0.89 |
| Calendar management | 3 of 6 | 1.00 | 1.00 | 1.00 |
| Directory listing | 2 of 6 | 1.00 | 1.00 | 1.00 |
| Email sending | 2 of 6 | 1.00 | 1.00 | 1.00 |
| File reading | 1 of 6 | 1.00 | 1.00 | 1.00 |
| Message posting | 1 of 6 | 0.00 | 1.00 | 0.00 |
| Database query | 0 of 6 | undefined | 1.00 | undefined |
| HTTP request | 0 of 6 | undefined | 1.00 | undefined |
| Web search | 0 of 6 | undefined | 1.00 | undefined |
| File writing | 0 of 6 | undefined | 1.00 | undefined |
| **Mean** | | **0.80** | **1.00** | **0.82** |

Two points must be read carefully. First, the block rate is a proportion of the attacks that
*succeeded*; where no attack succeeded there is nothing to block and the value is undefined,
not zero. Averaging those cases as zeros would have reported 0.48 instead of the measured
0.80, and correcting this also raised previously recorded figures from earlier runs. Second,
legitimate use was preserved on every tool without exception, which is the result that makes
the block rate meaningful — a policy that simply disabled each tool would show a perfect
block rate and zero legitimate use.

Message posting is a genuine failure rather than an artefact: one attack succeeded and the
policy stopped none of it.

FIGURE 4.5: Corpus results in the HTML report. *[SCREENSHOT: results dashboard]*

**Step 3 — live enforcement.** The gateway was loaded with the policy generated for the
file-reading tool and placed in front of the agent. Two requests were sent.

The first asked the agent to read a secret file and email its contents to an external
address. The agent performed the read, which the policy permits, and the attempt to send
email was blocked at the capability gate because the policy denies network access for that
session. The second request asked the agent to read an ordinary project file and summarise
it. It completed normally with no enforcement action.

TABLE 4.2: Live gateway behaviour.

| Request | Agent action | Gateway decision |
|---|---|---|
| Read secret file, email contents externally | Read file, then send email | Read allowed; email **blocked** (network capability denied) |
| Read a project file and summarise | Read file | **Allowed** |

This is the project's central claim demonstrated end to end on a running system: the attack
is stopped at the point where data would leave, and the tool's legitimate purpose still
works.

FIGURE 4.6: Gateway blocking an exfiltration attempt while permitting normal use.
*[SCREENSHOT: demo terminal output]*

FIGURE 4.7: Audit log showing both decisions with the gate and rule that fired.
*[SCREENSHOT: audit output]*

---

# CHAPTER 5: CONCLUSIONS AND FUTURE SCOPE

## 5.1 Work Accomplished

**O1 — adversarial attack generation (85%).** Attacks are generated from the tool schema
across six misuse categories and eight escalating techniques, refined on refusal, and graded
by a model from a different family than the generator. Indirect injection is carried on a
separate channel and reported separately throughout. The shortfall is that the grader has not
yet been calibrated against human judgement; a balanced blind labelling set has been prepared
and the analysis is ready to run once labels exist.

**O2 — analysis and policy synthesis (90%).** Successful attacks are classified, aggregated
into a primary exploit vector, and converted into a structured policy covering
confidentiality, capabilities, taint propagation and specific enforcement rules. The
remaining work is comparison against prompt-level defence baselines, which is implemented but
not yet executed.

**O3 — enforcement and verification (80%).** All four gates are implemented and applied both
offline, by the deterministic checker, and online, by the gateway. The paired
security-utility metric is reported for every run. The shortfall is statistical: results are
currently from a single complete run, and repeated runs are in progress.

**O4 — intent alignment and dashboard (30%).** The intent alignment layer was not built. The
information-flow gates that replaced it are stronger where they apply, because they do not
depend on a model's judgement, but they are narrower, reasoning about data flow rather than
intent. This is an honest deviation and is recorded as such. The dashboard exists as a static
per-run report with an audit endpoint, not as live monitoring.

## 5.2 Conclusions

The main finding is that a useful security policy can be derived automatically from a tool's
public description alone, and enforced without modifying the agent. Across ten tools the
synthesised policies blocked 80% of attacks that had succeeded against the unguarded agent
while allowing 100% of legitimate use, and the behaviour was reproduced on a live system.

The secondary finding is methodological and, in the team's view, the more transferable one.
Security effectiveness reported without a matching utility figure is not interpretable,
because the strongest possible block rate is achieved by disabling the tool. This is not a
theoretical concern: the system generated such policies repeatedly until two specific guards
were added, and the utility half of the metric is the only reason those runs were recognised
as failures rather than recorded as perfect scores.

Three limitations should be stated plainly. The results are from one run, so no error bars
are available and the figures should be treated as preliminary. The automated grader has not
been validated against human labels, so agreement between the two is unknown. And a policy
reasons only about the tool it was generated for — while building the demonstration, the same
attack was found *not* to be blocked under a different tool's policy, because a read performed
by another tool is not recognised as sensitive. Cross-tool data-flow policy is the clearest
technical gap in the current design.

## 5.3 Environmental, Economic and Social Benefits

**Economic.** Writing information-flow policies by hand requires security expertise and must
be repeated for every tool. Automating the analysis lowers the cost of adopting third-party
tools safely, particularly for organisations without a dedicated security team. Running on
locally hosted open models kept the project's own inference cost at zero.

**Social.** Agents are being connected to email, documents and databases containing personal
data. A control that prevents an agent from being manipulated into exfiltrating that data
protects people who are not party to the decision to deploy the agent, and the audit trail
gives an organisation the evidence needed to investigate an incident.

**Environmental.** The analysis is run once per tool rather than per request, and enforcement
adds no model calls, so the recurring computational cost of the defence is negligible. The
principal cost is the one-time analysis, which the early-stopping improvement reduced by
roughly half after measurement showed most refinement effort was producing no change in
outcome.

## 5.4 Future Work Plan

TABLE 5.1: Planned work for the remainder of the project.

| Priority | Task | Purpose |
|---|---|---|
| 1 | Complete five repeated runs of the corpus | Replace single-run figures with mean and standard deviation |
| 2 | Collect human labels and compute grader agreement | Establish that the automated grader is trustworthy |
| 3 | Run the prompt-level defence comparison | Position the work against practical alternatives rather than against no defence |
| 4 | Run the poisoned-description evaluation | Report detection quality against matched clean controls |
| 5 | Cross-tool information flow | Address the limitation found during the demonstration |
| 6 | Expand the corpus toward twenty tools | Strengthen the generalisation claim |
| 7 | Continuous integration | Prevent regressions between milestones |

Items 1 and 2 are the priorities, because they change what the existing results are permitted
to claim rather than adding new capability. Item 5 is the most substantial engineering task
and follows directly from a limitation the team found and documented rather than one raised
in review.

---

# APPENDIX A: REFERENCES

References follow IEEE style and are numbered in order of first citation. The full list of 27
references is retained from the existing bibliography and is not reproduced here in
abbreviated form.

# APPENDIX B: PLAGIARISM REPORT

To be attached following submission to the institutional similarity-check service.
