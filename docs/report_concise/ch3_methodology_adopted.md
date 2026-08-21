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
