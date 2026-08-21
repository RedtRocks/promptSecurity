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
