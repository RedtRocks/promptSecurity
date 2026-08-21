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

TABLE 4.1: Security-utility results, ten-tool corpus, mean +/- standard deviation over five
independent runs, after enforcement-rule schema validation.

| Tool | Attacks blocked | Legitimate use allowed | F1 |
|---|---|---|---|
| Calendar management | 1.00 +/- 0.00 | 1.00 +/- 0.00 | 1.00 |
| Message posting | 1.00 +/- 0.00 | 1.00 +/- 0.00 | 1.00 |
| File reading | 1.00 +/- 0.00 | 1.00 +/- 0.00 | 1.00 |
| File writing | 1.00 +/- 0.00 | 1.00 +/- 0.00 | 1.00 |
| Directory listing | 0.85 +/- 0.14 | 1.00 +/- 0.00 | 0.91 |
| Command execution | 0.67 +/- 0.29 | 1.00 +/- 0.00 | 0.77 |
| Email sending | 0.58 +/- 0.37 | 1.00 +/- 0.00 | 0.66 |
| Database query | undefined | 1.00 +/- 0.00 | undefined |
| HTTP request | undefined | 1.00 +/- 0.00 | undefined |
| Web search | undefined | 1.00 +/- 0.00 | undefined |
| **Mean** | **0.87** | **1.00** | **0.91** |

TABLE 4.2: Effect of enforcement-rule schema validation, five runs before and after.

| Measure | Before | After |
|---|---|---|
| Rules referencing a non-existent parameter | 34% | 5% |
| Attacks blocked | 0.68 | **0.87** |
| Legitimate use allowed | 0.99 | **1.00** |
| F1 | 0.69 | **0.91** |

Three points must be read carefully. First, the block rate is a proportion of the attacks
that *succeeded*; where no attack succeeded there is nothing to block and the value is
undefined rather than zero.

Second, legitimate use is now preserved on every tool. The security gain therefore did not
come from blocking more indiscriminately, which would have shown up as lost utility.

Third, the improvement in Table 4.2 came from a defect in policy *generation*, not policy
*design*. Enforcement rules are written by a language model, which routinely invented
parameter names the tool did not have — guarding a parameter called ``file_path`` on a tool
whose argument is ``path``. Such a rule fails open rather than closed: the checker's
fail-safe only widens a rule that has no argument condition at all, whereas a condition on a
parameter that never exists simply evaluates to false, so a correct-looking blocking rule
never fires. A third of all generated rules were affected. Validating rules against the
tool's declared schema, repairing near-misses and discarding conditions that cannot be
resolved, raised the block rate from 0.68 to 0.87 and removed both of the failures reported
earlier: message posting rose from 0.25 to 1.00 and file writing from 0.00 to 1.00.

Email sending is the one tool that fell, from 1.00 to 0.58, and the comparison is not
like-for-like: attacks succeeded against it fifteen times after the change against eight
before, so the later figure is measured over a larger and harder set. Inspection of its worst
run showed the remaining attacks were audited rather than blocked, and that one rule invoked
a predicate function the model had invented outright. Schema validation checks parameter
names, not fabricated predicates, so that class of defect remains open and is recorded as
future work.

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
