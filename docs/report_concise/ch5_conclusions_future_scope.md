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
public description alone, and enforced without modifying the agent. Across ten tools and five independent runs the synthesised policies blocked 87% of attacks
that had succeeded against the unguarded agent while allowing 100% of legitimate use, and
the behaviour was reproduced on a live system. Email sending is the weakest tool at 0.58,
with wide variance across runs.

The secondary finding is methodological and, in the team's view, the more transferable one.
Security effectiveness reported without a matching utility figure is not interpretable,
because the strongest possible block rate is achieved by disabling the tool. This is not a
theoretical concern: the system generated such policies repeatedly until two specific guards
were added, and the utility half of the metric is the only reason those runs were recognised
as failures rather than recorded as perfect scores.

Three limitations should be stated plainly. Two findings about evaluation are worth as much as the headline number. First, the estimate
is unstable in a way that repeated runs are needed to expose: after three and four runs the
mean block rate stood at 0.83 and appeared converged to three decimal places, and only the
fifth run revealed a tool the policy could not defend at all. Second, and more seriously,
a third of all generated enforcement rules referenced parameters the target tool does not
have, and such rules fail open rather than closed. Correcting this raised the block rate
from 0.68 to 0.87 at no cost to legitimate use. Both defects were invisible without repeated
runs and per-rule inspection, and neither would have been caught by measuring attack
blocking alone. The automated grader has not
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
