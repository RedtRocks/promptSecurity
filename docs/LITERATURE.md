# Literature Review

Scope: security of LLM agents that call tools, with emphasis on (i) prompt injection
delivered through tool-mediated channels, (ii) Model Context Protocol (MCP) tool
poisoning, (iii) system-level / information-flow defenses as opposed to prompt-level
ones, and (iv) automated red-teaming and security-policy synthesis. This is the
literature that `agent-hardener` sits in: a pipeline that attacks a single MCP tool
definition, measures what worked against a live agent, and synthesizes plus enforces
an information-flow policy for that tool.

Every reference below was checked against its canonical source. arXiv entries that
have not (to our knowledge) appeared in a peer-reviewed venue are marked
**[preprint]** in the reference list. Per-citation verification status is tracked in
`docs/references_to_verify.md`.

---

## 1. Prompt injection: attacks and formalization

The field's founding observation is that an LLM has no architectural separation
between the instructions it was given and the data it is asked to process. Liu et
al. [1] made this concrete at application scale with HouYi, a black-box attack that
decomposes injection into a framework component, a context-partitioning separator,
and a payload; 31 of 36 commercial LLM-integrated applications tested were
susceptible. That paper is the empirical case that injection is not a laboratory
curiosity. Liu et al. [2] then supplied the missing formal treatment: a unified
framework in which naive injection, escape characters, context ignoring, and fake
completion are instances of one construction, evaluated as a common benchmark across
5 attacks, 10 defenses, 10 models and 7 tasks. Their contribution to methodology
matters more than any single number — before it, the literature was a pile of
incomparable case studies.

Two properties of this attack class recur throughout the rest of the review. First,
the attacks are *cheap and automatable*: Liu et al. [3] show gradient-based
optimization produces universal injection strings from ~0.3% of a test set, and warn
explicitly that defenses evaluated only against hand-written attacks will be
overestimated. Second, success is *not binary at the prompt level* — it depends on
whether the model's downstream action is consequential, which is why the tool-using
setting (Sections 2–3) is where injection becomes a security problem rather than an
output-quality problem.

A design-level diagnosis has emerged in parallel. Wallace et al. [4] argue the root
cause is that models treat system, user, and tool-returned text as equally
privileged, and propose training an explicit *instruction hierarchy*. This reframes
injection as a missing privilege model — the same framing that motivates the
capability and taint machinery in Section 5, and the framing this project adopts at
the dispatch boundary rather than in the weights.

## 2. Indirect injection and tool-mediated attacks

Greshake et al. [5] introduced the threat model that most of this project targets:
the attacker never talks to the model. They plant instructions in content the model
will *retrieve* — a web page, a document, an email — and demonstrated working attacks
against Bing Chat and code-completion products, with a security-perspective taxonomy
covering data theft, self-propagation, and information contamination. The essential
change from Section 1 is the trust boundary: the user's turn is benign, so any
defense that scrutinizes the user's request is looking in the wrong place.

Zhan et al. [6] operationalized this for tool-using agents with InjecAgent: 1,054
test cases over 17 user tools and 62 attacker tools, split by attacker objective into
direct user harm and private-data exfiltration. Their headline — a ReAct-prompted
GPT-4 acting on injected instructions 24% of the time, roughly doubling under
reinforced prompts — establishes both that the attack works and that the agent's
*loop structure* is part of the attack surface. That finding is load-bearing for this
project: a single-shot planner that commits to a plan before observing any tool
output cannot express indirect injection at all, which is why the evaluation agent
here runs a bounded ReAct loop.

Ruan et al. [7] approach the same space from the risk-discovery side with ToolEmu,
using an LM to emulate tool execution so that high-stakes tools (36 of them, 144
cases) can be exercised without real-world side effects, with 68.8% of identified
failures judged valid by human review. The tradeoff is explicit and is one this
project inherits: emulated execution buys safe adversarial testing at the cost of
fidelity to real tool behavior.

## 3. Agent security benchmarks and evaluation harnesses

Three benchmarks define the evaluation norms, and they disagree usefully about what
should be measured.

AgentDojo [8] is the most influential: 97 realistic tasks (email, banking, travel)
and 629 security test cases in an *extensible environment* rather than a fixed
dataset, deliberately built so new attacks and adaptive defenses can be added. Its
crucial methodological choice is scoring utility and security together — a defense
that breaks the agent is not a good defense — and this dual scoring is what
downstream work, including CaMeL [16] and this project's ABR/BPR/F1, reports against.

AgentHarm [9] measures a different thing: whether an agent will *comply* with an
explicitly malicious user across 110 tasks and 11 harm categories. Its finding that
leading models are "surprisingly compliant" without any jailbreak is important, but
the threat model is a malicious user, not a compromised data channel. This project
originally used the AgentHarm harm taxonomy as its attack axis and has since
demoted it to a secondary comparability field, for exactly this reason: content-harm
categories do not describe what a *tool* can be abused for, and instructing a file
reader to produce hate speech fails for reasons unrelated to the tool's security.

Agent Security Bench [10] is the broadest sweep — 10 scenarios, 400+ tools, 27
attack/defense methods, 13 backbones — and reports attack success up to 84.3% with
existing defenses providing limited protection. Read together, [8]–[10] give a
consistent picture: attack success against undefended tool-using agents is high, and
the defenses in the literature at the time moved it far less than their authors
hoped. They also share a limitation this project responds to: all three ship a
*fixed* attack suite and none emits a deployable defense artifact. They evaluate; they
do not harden.

## 4. Prompt-level and model-level defenses

The cheapest defenses operate on the prompt. Hines et al. [11] introduced
spotlighting/datamarking: transform untrusted input so its provenance is continuously
signaled to the model (delimiting, datamarking, encoding), reducing attack success
from >50% to <2% on GPT-family models with minimal task-efficacy loss. Those numbers
set the bar honestly: any system-level defense claiming value must either beat that
frontier or claim a different property. This project implements spotlighting,
instruction defense, sandwich, and prompt-level sink restriction as baseline
conditions (`agent_hardener/defenses.py`) precisely so the comparison is not
"policy vs. nothing".

Model-level defenses harden the weights instead of the prompt. Chen et al. [12]
propose StruQ, a structured-query interface plus a model fine-tuned to ignore
instructions appearing in the data channel; Chen et al. [13] extend this with
SecAlign, framing the defense as preference optimization over (secure, insecure)
response pairs and reporting substantially lower success rates against optimization-
based attacks. Wallace et al. [4] pursue the same goal through hierarchical
instruction training.

The shared limitation of Sections 4's defenses is the one that motivates Section 5:
they are all *probabilistic and model-resident*. They reduce the chance the model
complies; none of them holds once the model does comply. Liu et al. [3] make the
sharper version of the point — defenses tuned against static attacks look better than
they are. This is the specific gap a runtime enforcement layer fills, and the
defensible claim for enforcement is independence from model compliance, not a higher
block rate.

## 5. System-level defenses and information-flow control

The classical foundations predate LLMs entirely. Myers and Liskov [14] introduced the
decentralized label model, in which data carries labels naming owners and readers and
declassification is an explicit, authorized act — the ancestor of the confidentiality
annotations and taint propagation in this project's SAMOS policy model. Sabelfeld and
Myers [15] survey language-based enforcement of noninterference and, importantly for
practitioners, catalogue why pure noninterference is too strong for real programs and
what controlled relaxations cost. Both papers explain why "block every flow" is a
trivially safe and trivially useless policy — the deny-all failure mode this project
guards against explicitly.

CaMeL [16] is the strongest modern instantiation and the closest prior art here. It
extracts control and data flow from the *trusted* user query into an explicit
program, runs untrusted data through a quarantined model that cannot influence
control flow, and attaches capabilities to values so exfiltration over unauthorized
data flows is prevented *at the point the tool is called*. On AgentDojo it solves 77%
of tasks with provable security against the modeled attacker class, versus 84%
undefended. Two things follow. First, security-by-construction for tool-using agents
is achievable. Second, it costs an agent rewrite: a custom interpreter and a
privileged/quarantined model split.

Beurer-Kellner et al. [17] generalize this into six design patterns with provable
injection resistance (action-selector, plan-then-execute, LLM map-reduce,
dual-LLM, code-then-execute, context-minimization), applied to ten case studies and
analyzed explicitly for the utility/security tradeoff. Their central claim — security
comes from constraining what the agent *may do*, not from better prompting — is the
argument this project's enforcement gates instantiate, and their patterns are a
useful vocabulary for describing what a synthesized per-tool policy lands on.

Two more system designs bracket the space. Wu et al. [18] give an information-flow-
control treatment with formal security guarantees, disaggregating the system into a
context-aware pipeline with dynamically generated structured plans plus a security
monitor filtering untrusted input. Wu et al. [19] (IsolateGPT, NDSS 2025) attack the
problem with execution isolation between third-party LLM apps, reporting protection
against several threat classes at under 30% overhead for most queries — the closest
prior work to this project's *deployment* story, since it too intervenes between an
agent and third-party extensions rather than inside the model.

The common limitation across [16]–[19] is architectural intrusiveness: each requires
adopting a new agent runtime. None of them synthesizes its policy from an
adversarially discovered attack surface.

## 6. MCP-specific security

MCP made the third-party-tool ecosystem concrete and, with it, a specific new attack
surface: the tool *description* is attacker-supplied text that the agent reads as
trusted. OWASP codifies this as `MCP03:2025 Tool Poisoning` [20], noting that one
poisoned schema replicated across tenants multiplies blast radius.

MCPTox [21] is the strongest empirical evidence: 1,312 malicious test cases built
from 45 real-world MCP servers and 353 authentic tools, evaluated over 20 agents,
with attack success as high as 72.8% (o1-mini) and refusal rates below 3% even for
the most conservative model tested. It is the attack-side reference for tool
poisoning and should be cited as such; a hand-built matched-control set (as here) is
a *detection* proof, not a competing benchmark. MCPXKIT [22] complements it with a
unified toolkit implementing 31 attack methods across four classes (direct tool
injection, indirect tool injection, malicious-user attacks, LLM-inherent attacks) and
identifies blind reliance on tool descriptions and difficulty separating external
data from executable commands as the recurring root causes. MCPGuard [23] surveys and
builds toward automated MCP server vulnerability detection, spanning server-side
scanning, auditing, and runtime monitoring.

The MCP security literature is young and skews attack-side and toolkit-side. What is
thin: end-to-end work that takes a *single* third-party tool definition, establishes
empirically what it can be abused for, and emits a runtime control specific to that
tool. Scope limits worth stating in any MCP work: cross-server tool shadowing, rug
pulls (a tool updated with harmful logic after approval), and MCP authorization /
confused-deputy issues are distinct problems from description poisoning and are not
addressed here.

## 7. Automated red-teaming and policy synthesis

The attack side of this project descends from automated red-teaming. Perez et al.
[24] established the template: use one LM to generate test cases against another,
uncovering tens of thousands of offensive replies plus privacy leaks in a deployed
chatbot, with a ladder of generation strategies (zero-shot, few-shot, supervised, RL)
trading off difficulty against diversity. Chao et al. [25] sharpened it into PAIR, in
which an attacker LLM iteratively refines a jailbreak against a black-box target
using feedback, typically succeeding in fewer than twenty queries. The
generate–observe–refine loop, and specifically *escalation on refusal*, is what this
project's Stage 1.3 refiner implements per tool.

On the synthesis side, Progent [26] is the nearest neighbor and should be treated as
such: it generates symbolic privilege-control policies for agents from the user task,
enforces them deterministically at tool-call time, and uses an SMT solver to
distinguish policy narrowing (auto-applied) from expansion (requires approval),
reporting reduced attack success at maintained utility on AgentDojo and ASB. The
distinction from this project is the policy's *unit and origin*: Progent's policy is
derived per user task from a trusted request; here the policy is derived per *tool*
from an adversarial probe of that tool's description and observed behavior, and the
tool description itself is treated as untrusted input rather than as ground truth.

---

## Comparison table

| Paper | Approach | Domain | Result | Limitation |
|---|---|---|---|---|
| Liu et al. (HouYi) [1] | Black-box injection with separator + payload | LLM-integrated apps | 31/36 commercial apps vulnerable | Attack only; no defense; manual attack construction |
| Liu et al. [2] | Formal framework + common benchmark | Prompt injection | 5 attacks × 10 defenses × 10 LLMs × 7 tasks | Text-completion tasks, not tool-using agents |
| Liu et al. [3] | Gradient-based universal injection | White-box LLMs | Universal strings from ~0.3% of data | Needs gradient access; not applicable to hosted models |
| Wallace et al. [4] | Instruction-hierarchy training | Model alignment | Large robustness gains on GPT-3.5, minor capability cost | Model-resident; fails once the model complies |
| Greshake et al. [5] | Indirect injection taxonomy + PoCs | LLM-integrated apps | Working attacks on Bing Chat, code completion | Taxonomy and demos; no quantitative benchmark |
| Zhan et al. (InjecAgent) [6] | Templated indirect injection benchmark | Tool-integrated agents | ReAct GPT-4 attacked 24% of the time | Fixed templates; no defense produced |
| Ruan et al. (ToolEmu) [7] | LM-emulated tool sandbox | Agent risk discovery | 68.8% of found failures human-validated | Emulated execution; fidelity gap to real tools |
| Debenedetti et al. (AgentDojo) [8] | Extensible attack/defense environment | Tool-using agents | 97 tasks, 629 security cases; utility + security scored | Fixed injection suite; evaluates, does not harden |
| Andriushchenko et al. (AgentHarm) [9] | Curated harmful-task benchmark | Agent misuse | 110 tasks; models compliant without jailbreak | Malicious-*user* threat model; content-harm axis |
| Zhang et al. (ASB) [10] | Broad attack/defense benchmark | LLM agents | ASR up to 84.3%; defenses weak | Breadth over depth; no deployable artifact |
| Hines et al. (Spotlighting) [11] | Provenance marking of untrusted input | Indirect injection | ASR >50% → <2%, minimal utility loss | Prompt-level; relies on model compliance |
| Chen et al. (StruQ) [12] | Structured query + fine-tuning | Prompt injection | Strong reduction with preserved utility | Requires model fine-tuning; not for hosted models |
| Chen et al. (SecAlign) [13] | Preference optimization on secure/insecure pairs | Prompt injection | Large ASR reduction incl. optimization attacks | Same: weight access required; probabilistic |
| Myers & Liskov (DLM) [14] | Decentralized labels + explicit declassification | IFC (classical) | Fine-grained sharing under mutual distrust | Pre-LLM; needs a labeled program, not NL |
| Sabelfeld & Myers [15] | Survey of language-based IFC | IFC (classical) | Canonical framing of noninterference + relaxations | Survey; strict noninterference too strong in practice |
| Debenedetti et al. (CaMeL) [16] | Control/data-flow extraction + capabilities at tool call | Tool-using agents | 77% AgentDojo solved with provable security (84% undefended) | Requires agent rewrite (interpreter, P-LLM/Q-LLM split) |
| Beurer-Kellner et al. [17] | Six design patterns with provable resistance | Agent architecture | 10 case studies, explicit utility/security analysis | Patterns, not an automated system; manual per-app |
| Wu et al. (f-secure) [18] | IFC pipeline + security monitor | LLM systems | Formal guarantees with retained utility | New runtime required; structured-plan assumption |
| Wu et al. (IsolateGPT) [19] | Execution isolation between LLM apps | LLM app ecosystems | Threats blocked at <30% overhead for most queries | Architectural change; isolation, not flow policy |
| OWASP MCP Top 10 [20] | Threat catalogue (`MCP03` Tool Poisoning) | MCP | Standard framing + controls | Guidance, not measurement |
| MCPTox [21] | Tool-poisoning benchmark on real servers | MCP | ASR 72.8% (o1-mini); refusal <3% | Attack-side only; no defense produced |
| MCPXKIT [22] | Unified toolkit, 31 attacks, 4 classes | MCP | Root causes: blind trust in descriptions | Toolkit/analysis; no runtime enforcement |
| MCPGuard [23] | Automated MCP server vulnerability detection | MCP | Scanning + auditing + runtime monitoring | Server-level; description-level detection unclear |
| Perez et al. [24] | LM-generated red-team test cases | LM safety | Tens of thousands of harmful replies found | Single-turn chat; no tools, no policy output |
| Chao et al. (PAIR) [25] | Attacker LLM iteratively refines jailbreak | Black-box LLMs | Jailbreaks in ≲20 queries | Content jailbreaks; not tool-abuse or agent actions |
| Shi et al. (Progent) [26] | Symbolic privilege policies enforced at tool call | LLM agents | Lower ASR at maintained utility (AgentDojo, ASB) | Policy derived from the *trusted user task*, per session |

---

## Positioning of this work

`agent-hardener` occupies a gap that is narrow but real: **per-tool,
description-derived attack-surface analysis that produces an enforceable
information-flow policy for an agent nobody rewrote.**

Relative to the benchmarks [8]–[10], the difference is the output artifact. They ship
a fixed attack suite and a score; this pipeline *generates* attacks per tool, escalates
on refusal [24], [25], and emits a `SAMOSPolicy` plus a gateway that enforces it —
then scores that policy on both sides (ABR and BPR, harmonic mean F1) so a deny-all
policy scores zero. Evaluation is not the contribution; the closed loop from attack to
enforced artifact is.

Relative to the prompt- and model-level defenses [4], [11]–[13], the difference is
where enforcement lives. Spotlighting's reported frontier (>50% → <2%) is a high bar,
and the honest claim here is **not** a higher block rate. It is that a deterministic
gate at the dispatch boundary holds *when the model has already complied* — enforcement
independent of model compliance. If `scripts/defense_baseline_eval.py` does not show
the policy beating spotlighting on the ABR/BPR frontier, that independence is the
result to report, not a buried baseline.

**CaMeL [16] is the closest prior art, and this work does not claim to beat it on
security.** CaMeL's guarantee is by construction for the flows it models; the policy
here is LLM-generated and therefore may be wrong or over-broad — every number is
*measured*, not proven. The delta is the operating point, stated narrowly: (a) no
agent rewrite — the policy wraps an existing agent at the tool-dispatch boundary,
where CaMeL requires a custom interpreter and a privileged/quarantined model split;
(b) the policy is *synthesized automatically per tool* rather than derived from a
trusted program; and (c) the tool **description** is treated as untrusted input
(OWASP `MCP03` [20]), whereas CaMeL's threat model trusts the query and does not cover
poisoning. Where an agent can be rebuilt, CaMeL is the stronger guarantee.

Progent [26] is the second-closest and the sharper comparison for the *synthesis*
claim. Both generate policies and enforce them deterministically at tool-call time.
Progent's unit is the user session, and its policy is derived from the trusted task
description; the unit here is the *tool*, and the policy is derived from an
adversarial probe of a description that is assumed hostile. Progent's SMT-backed
narrow/expand discipline is a formal property this work does not have, and should be
cited as such rather than glossed over.

Against the MCP literature [20]–[23], the poisoning experiment here is a **detection**
result on a small matched-control set, not a benchmark. MCPTox [21] — 45+ real
servers, 1,312 cases — is the attack-side reference and must be cited as the stronger
evidence; the claim here is only that a description-derived analysis pipeline notices
poisoning while maintaining a measured false-positive rate against matched clean
controls. Scope limits stated plainly: cross-server tool shadowing, rug pulls, and MCP
authorization/confused-deputy issues are out of scope, and tool *implementations* are
never modified — the honest framing is description-derived attack-surface analysis
plus runtime policy synthesis.

Finally, the classical IFC lineage [14], [15] is what the SAMOS label model borrows
from, and also what supplies this project's central caution: noninterference is
trivial to satisfy by refusing everything. The two anti-deny-all guards and the F1
metric exist because the generated policies reached for capability denial repeatedly
— the gameability of a security-only metric is not hypothetical here, it is the
observed failure mode.

---

## References

[1] Y. Liu, G. Deng, Y. Li, K. Wang, Z. Wang, X. Wang, T. Zhang, Y. Liu, H. Wang,
Y. Zheng, L. Y. Zhang, and Y. Liu, "Prompt injection attack against LLM-integrated
applications," arXiv:2306.05499, 2023. **[preprint]**

[2] Y. Liu, Y. Jia, R. Geng, J. Jia, and N. Z. Gong, "Formalizing and benchmarking
prompt injection attacks and defenses," in *Proc. 33rd USENIX Security Symposium*,
2024.

[3] X. Liu, Z. Yu, Y. Zhang, N. Zhang, and C. Xiao, "Automatic and universal prompt
injection attacks against large language models," arXiv:2403.04957, 2024.
**[preprint]**

[4] E. Wallace, K. Xiao, R. Leike, L. Weng, J. Heidecke, and A. Beutel, "The
instruction hierarchy: Training LLMs to prioritize privileged instructions,"
arXiv:2404.13208, 2024. **[preprint]**

[5] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, "Not what
you've signed up for: Compromising real-world LLM-integrated applications with
indirect prompt injection," arXiv:2302.12173, 2023.

[6] Q. Zhan, Z. Liang, Z. Ying, and D. Kang, "InjecAgent: Benchmarking indirect prompt
injections in tool-integrated large language model agents," in *Findings of the
Association for Computational Linguistics: ACL 2024*, 2024.

[7] Y. Ruan, H. Dong, A. Wang, S. Pitis, Y. Zhou, J. Ba, Y. Dubois, C. J. Maddison,
and T. Hashimoto, "Identifying the risks of LM agents with an LM-emulated sandbox,"
arXiv:2309.15817, 2023. **[preprint]**

[8] E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and
F. Tramèr, "AgentDojo: A dynamic environment to evaluate prompt injection attacks and
defenses for LLM agents," in *Advances in Neural Information Processing Systems 37
(NeurIPS Datasets and Benchmarks Track)*, 2024.

[9] M. Andriushchenko, A. Souly, M. Dziemian, D. Duenas, M. Lin, J. Wang,
D. Hendrycks, A. Zou, Z. Kolter, M. Fredrikson, E. Winsor, J. Wynne, Y. Gal, and
X. Davies, "AgentHarm: A benchmark for measuring harmfulness of LLM agents," in
*Proc. International Conference on Learning Representations (ICLR)*, 2025.

[10] H. Zhang, J. Huang, K. Mei, Y. Yao, Z. Wang, C. Zhan, H. Wang, and Y. Zhang,
"Agent Security Bench (ASB): Formalizing and benchmarking attacks and defenses in
LLM-based agents," in *Proc. International Conference on Learning Representations
(ICLR)*, 2025.

[11] K. Hines, G. Lopez, M. Hall, F. Zarfati, Y. Zunger, and E. Kiciman, "Defending
against indirect prompt injection attacks with spotlighting," arXiv:2403.14720, 2024.
**[preprint]**

[12] S. Chen, J. Piet, C. Sitawarin, and D. Wagner, "StruQ: Defending against prompt
injection with structured queries," in *Proc. 34th USENIX Security Symposium*, 2025.

[13] S. Chen, A. Zharmagambetov, S. Mahloujifar, K. Chaudhuri, D. Wagner, and C. Guo,
"SecAlign: Defending against prompt injection with preference optimization," in
*Proc. ACM SIGSAC Conference on Computer and Communications Security (CCS)*, 2025.

[14] A. C. Myers and B. Liskov, "A decentralized model for information flow control,"
in *Proc. 16th ACM Symposium on Operating Systems Principles (SOSP)*, 1997,
pp. 129–142. doi: 10.1145/268998.266669.

[15] A. Sabelfeld and A. C. Myers, "Language-based information-flow security," *IEEE
Journal on Selected Areas in Communications*, vol. 21, no. 1, pp. 5–19, Jan. 2003.
doi: 10.1109/JSAC.2002.806121.

[16] E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern,
C. Shi, A. Terzis, and F. Tramèr, "Defeating prompt injections by design,"
arXiv:2503.18813, 2025. **[preprint]**

[17] L. Beurer-Kellner, B. Buesser, A.-M. Creţu, E. Debenedetti, D. Dobos, D. Fabian,
M. Fischer, D. Froelicher, K. Grosse, D. Naeff, E. Ozoani, A. Paverd, F. Tramèr, and
V. Volhejn, "Design patterns for securing LLM agents against prompt injections,"
arXiv:2506.08837, 2025. **[preprint]**

[18] F. Wu, E. Cecchetti, and C. Xiao, "System-level defense against indirect prompt
injection attacks: An information flow control perspective," arXiv:2409.19091, 2024.
**[preprint]**

[19] Y. Wu, F. Roesner, T. Kohno, N. Zhang, and U. Iqbal, "IsolateGPT: An execution
isolation architecture for LLM-based agentic systems," in *Proc. Network and
Distributed System Security Symposium (NDSS)*, 2025.

[20] OWASP Foundation, "MCP03:2025 – Tool poisoning," *OWASP MCP Top 10*, 2025.
[Online]. Available: https://owasp.org/www-project-mcp-top-10/

[21] Z. Wang, Y. Gao, Y. Wang, S. Liu, H. Sun, H. Cheng, G. Shi, H. Du, and X. Li,
"MCPTox: A benchmark for tool poisoning attack on real-world MCP servers,"
arXiv:2508.14925, 2025. **[preprint]**

[22] Y. Guo, P. Liu, W. Ma, Z. Deng, X. Zhu, P. Di, X. Xiao, and S. Wen, "MCPXKIT: The
unified toolkit for analyzing Model Context Protocol security," arXiv:2508.12538,
2025. **[preprint]**

[23] B. Wang, Z. Liu, H. Yu, A. Yang, Y. Huang, J. Guo, H. Cheng, H. Li, and H. Wu,
"MCPGuard: Automatically detecting vulnerabilities in MCP servers,"
arXiv:2510.23673, 2025. **[preprint]**

[24] E. Perez, S. Huang, F. Song, T. Cai, R. Ring, J. Aslanides, A. Glaese,
N. McAleese, and G. Irving, "Red teaming language models with language models," in
*Proc. Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 2022.

[25] P. Chao, A. Robey, E. Dobriban, H. Hassani, G. J. Pappas, and E. Wong,
"Jailbreaking black box large language models in twenty queries," arXiv:2310.08419,
2023. **[preprint]**

[26] T. Shi, J. He, Z. Wang, H. Li, L. Wu, W. Guo, and D. Song, "Progent: Securing AI
agents with privilege control," arXiv:2504.11703, 2025. **[preprint]**

[27] Anthropic, "Model Context Protocol specification." [Online]. Available:
https://modelcontextprotocol.io/ — *pin the exact spec revision the evaluation agent
targets before camera-ready.*
