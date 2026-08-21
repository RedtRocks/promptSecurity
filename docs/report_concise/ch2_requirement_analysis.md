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
