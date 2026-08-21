# SECUREAGENT

## Adversarial Attack Surface Analysis and Runtime Policy Enforcement for AI Agent Tools

Capstone Project Report

MID SEMESTER EVALUATION

Submitted by:

(102303179) AARAV DUDEJA
(102303904) AKSHAT SRIVASTAVA
(102306026) HITEN YADAV
(102317215) SANIL GROVER
(102306046) SIMRAN ARORA

BE Fourth Year, COE/CSE

CPG No: 215

Under the Mentorship of

**Dr. Gurpal Singh Chhabra**
Assistant Professor, CSE

**Dr. Amit Kumar Trivedi**
Assistant Professor, CSE

*[LOGO: Thapar Institute of Engineering & Technology crest, centred]*

Computer Science and Engineering Department
Thapar Institute of Engineering and Technology, Patiala

August 2026

---

# ABSTRACT

AI agents built on large language models increasingly act on the world through tools —
reading files, querying databases, sending email and executing commands — and the Model
Context Protocol (MCP) has made those tools trivially shareable between organisations.
This creates a security boundary that current practice does not defend: when an agent
connects to a third-party MCP server, the tool's natural-language description is supplied
by that third party but is read by the agent as trusted instruction text. OWASP catalogues
this as `MCP03:2025 Tool Poisoning`. Published measurements find attack success rates of
24% for indirect injection against a ReAct-prompted GPT-4, up to 84.3% across a broad
agent-security sweep, and up to 72.8% against agents using real MCP servers.

Existing defenses occupy two extremes. Prompt-level mitigations such as spotlighting are
inexpensive and reduce attack success from over 50% to under 2%, but they are
model-resident and probabilistic — they lower the chance the model complies and offer
nothing once it does. System-level defenses such as CaMeL provide far stronger guarantees
but require rewriting the agent around a custom interpreter and a privileged/quarantined
model split. Organisations that can neither modify the model nor rewrite the agent are
left without a control.

SecureAgent addresses that gap. Given a single MCP tool definition, it generates
schema-aware adversarial attacks across six tool-misuse objectives and eight ranked
red-team techniques, dispatches them to a live agent, and escalates to a stronger
technique whenever the agent refuses — so a refusal advances the search rather than ending
it. Every successful attack is classified into a five-type exploit taxonomy and compiled
into a SAMOS information-flow policy carrying confidentiality annotations, capability
allowed-sets, session taint rules and enforcement rules with three response modes. A
deterministic verifier then replays trajectories through that policy with no model call in
the loop, applying four gates: capability denial, a confidentiality taint gate that stops
secret data flowing out, an integrity taint gate that stops attacker-controlled
instructions being acted upon, and argument-aware enforcement rules that discriminate on
parameter values rather than tool identity alone. Because attack-block rate alone is
gameable — a policy that disables the tool blocks every attack and every legitimate use —
the same gates are replayed over a suite of benign tasks, and results are reported as
attack block rate, benign pass rate and their harmonic mean, so a deny-all policy scores
zero. Two generator-side guards exist specifically because that degenerate policy was
produced repeatedly in practice.

The system comprises 16,802 lines of Python across 69 files, including 205 tests, a
ten-tool MCP corpus with paired benign-task suites, seven poisoned tool descriptions with
matched clean controls, and a FastAPI gateway that enforces the synthesised policy in
front of an unmodified agent. A preliminary evaluation across the corpus (n = 3 runs,
explicitly not final) yields a mean benign pass rate of 0.94 with no degenerate deny-all
policy, and non-trivial security on argument- and flow-based tools.

Against the four panel-approved objectives, the project stands at **71% weighted
completion**: the Red Agent and Defender Agent are substantially complete, the Policy
Enforcement Engine is complete, the Policy Verification Loop is implemented but not yet
executed, the Security Dashboard is delivered as a static report rather than a live
monitoring interface, and the Intent Alignment Layer was superseded by deterministic
information-flow gates and has not been built. The report states each divergence
explicitly and argues the substitution rather than concealing it.

**Keywords:** LLM agent security, prompt injection, Model Context Protocol, tool
poisoning, information-flow control, policy synthesis, runtime enforcement.

---

# DECLARATION

We hereby declare that the design principles and working prototype model of the project
entitled **SecureAgent — Adversarial Attack Surface Analysis and Runtime Policy
Enforcement for AI Agent Tools** is an authentic record of our own work carried out in the
Computer Science and Engineering Department, TIET, Patiala, under the guidance of
**Dr. Gurpal Singh Chhabra** and **Dr. Amit Kumar Trivedi** during 7th semester (2026).

Date: _______________

| Roll No. | Name | Signature |
|---|---|---|
| 102303179 | Aarav Dudeja | ---- |
| 102303904 | Akshat Srivastava | ---- |
| 102306026 | Hiten Yadav | ---- |
| 102317215 | Sanil Grover | ---- |
| 102306046 | Simran Arora | ---- |

*Counter Signed By:*

| Faculty Mentor: | Co-Mentor: |
|---|---|
| Dr. Gurpal Singh Chhabra | Dr. Amit Kumar Trivedi |
| Assistant Professor | Assistant Professor |
| CSED, | CSED, |
| TIET, Patiala | TIET, Patiala |

> **Note on template deviation:** the supplied template's declaration boilerplate reads
> *"during 6th semester (2024)"*. This is a Fourth Year project submitted in August 2026;
> the semester and year have been corrected accordingly. Confirm the expected semester
> number with the department before final submission.

---

# ACKNOWLEDGEMENT

We would like to express our thanks to our mentors **Dr. Gurpal Singh Chhabra** and
**Dr. Amit Kumar Trivedi**. They have been of great help in our venture and an
indispensable resource of technical knowledge. They are truly amazing mentors to have.

We are also thankful to the Head, Computer Science and Engineering Department, the entire
faculty and staff of the Computer Science and Engineering Department, and also our friends
who devoted their valuable time and helped us in all possible ways towards successful
completion of this project. We thank all those who have contributed either directly or
indirectly towards this project.

Lastly, we would also like to thank our families for their unyielding love and
encouragement. They always wanted the best for us and we admire their determination and
sacrifice.

Date: _______________

| Roll No. | Name | Signature |
|---|---|---|
| 102303179 | Aarav Dudeja | ---- |
| 102303904 | Akshat Srivastava | ---- |
| 102306026 | Hiten Yadav | ---- |
| 102317215 | Sanil Grover | ---- |
| 102306046 | Simran Arora | ---- |

---

# TABLE OF CONTENTS

| Section | Page No. |
|---|---|
| ABSTRACT | i |
| DECLARATION | ii |
| ACKNOWLEDGEMENT | iii |
| LIST OF FIGURES | iv |
| LIST OF TABLES | v |
| LIST OF ABBREVIATIONS | vi |
| **CHAPTER** | **Page No.** |
| **1. Introduction** | 1 |
| 1.1 Project Overview | 1 |
| 1.2 Need Analysis | 5 |
| 1.3 Research Gaps | 6 |
| 1.4 Problem Definition and Scope | 8 |
| 1.5 Assumptions and Constraints | 9 |
| 1.6 Standards | 11 |
| 1.7 Approved Objectives | 12 |
| 1.8 Methodology | 15 |
| 1.9 Project Outcomes and Deliverables | 16 |
| 1.10 Novelty of Work | 17 |
| **2. Requirement Analysis** | 19 |
| 2.1 Literature Survey | 19 |
| 2.2 Software Requirement Specification | 30 |
| 2.3 Cost Analysis | 38 |
| 2.4 Risk Analysis | 41 |
| **3. Methodology Adopted** | 44 |
| 3.1 Investigative Techniques | 44 |
| 3.2 Proposed Solution | 47 |
| 3.3 Work Breakdown Structure | 51 |
| 3.4 Tools and Technology | 54 |
| **4. Design Specifications** | 57 |
| 4.1 System Architecture | 57 |
| 4.2 Design Level Diagrams | 60 |
| 4.3 User Interface Diagrams | 68 |
| 4.4 Snapshots of Working Prototype | 70 |
| **5. Conclusions and Future Scope** | 78 |
| 5.1 Work Accomplished | 78 |
| 5.2 Conclusions | 82 |
| 5.3 Environmental / Economic / Social Benefits | 84 |
| 5.4 Future Work Plan | 85 |
| **APPENDIX A: References** | 89 |
| **APPENDIX B: Plagiarism Report** | 93 |

> **[VERIFY: page numbers above are placeholders.** They must be regenerated from the
> assembled document. The `.docx` build generates a live table of contents; these values
> exist only so the markdown source is reviewable.]

---

# LIST OF FIGURES

| Figure No. | Caption | Page No. |
|---|---|---|
| Figure 1.1 | Three-stage architecture of the SecureAgent pipeline | 3 |
| Figure 2.1 | System context diagram | 33 |
| Figure 3.1 | Investigative method — control and treatment conditions | 46 |
| Figure 3.2 | Proposed solution — end-to-end data flow | 49 |
| Figure 3.3 | Work breakdown structure | 52 |
| Figure 4.1 | System architecture — layered view | 58 |
| Figure 4.2 | Use case diagram | 61 |
| Figure 4.3 | Class diagram — core data contracts | 63 |
| Figure 4.4 | Sequence diagram — attack and refinement cycle | 65 |
| Figure 4.5 | Activity diagram — four-gate policy verification | 66 |
| Figure 4.6 | Entity-relationship diagram — artifact data model | 67 |
| Figure 4.7 | Terminal user interface layout | 69 |
| Figure 4.8 | HTML report dashboard layout | 70 |
| Figure 4.9 | Gateway request path | 76 |
| Figure 5.1 | Objective completion by sub-deliverable | 79 |
| Figure 5.2 | Future work timeline | 87 |

---

# LIST OF TABLES

| Table No. | Caption | Page No. |
|---|---|---|
| Table 1.1 | Project assumptions | 9 |
| Table 1.2 | Project constraints | 10 |
| Table 1.3 | Standards and specifications | 11 |
| Table 1.4 | Approved-proposal terminology mapped to the refined implementation | 13 |
| Table 1.5 | Completion per sub-deliverable | 14 |
| Table 1.6 | Deliverables and the objective each serves | 16 |
| Table 2.1 | Comparison of prior work | 24 |
| Table 2.2 | Literature survey apportioned by team member | 26 |
| Table 2.3 | Tools and technologies surveyed | 29 |
| Table 2.4 | Cost model assumptions | 38 |
| Table 2.5 | Unit prices by provider | 39 |
| Table 2.6 | Three-scenario cost comparison | 40 |
| Table 2.7 | Project risk register | 41 |
| Table 2.8 | Risk exposure summary | 43 |
| Table 3.1 | Investigative techniques | 44 |
| Table 3.2 | Attack objectives and enforcement gates | 48 |
| Table 3.3 | Work breakdown by module and owner | 53 |
| Table 3.4 | Technology selection and justification | 55 |
| Table 4.1 | Architectural layers and responsibilities | 59 |
| Table 4.2 | Core data contracts | 62 |
| Table 4.3 | Gateway API surface | 76 |
| Table 5.1 | Work accomplished against approved objectives | 78 |
| Table 5.2 | Preliminary corpus results | 80 |
| Table 5.3 | Future work plan and timeline | 86 |

---

# LIST OF ABBREVIATIONS

| Abbreviation | Expansion |
|---|---|
| ABR | Attack Block Rate |
| API | Application Programming Interface |
| ASR | Attack Success Rate |
| BPR | Benign Pass Rate |
| CI | Confidence Interval |
| CLI | Command Line Interface |
| DLM | Decentralized Label Model |
| F1 | Harmonic mean of ABR and BPR |
| FQDN | Fully Qualified Domain Name |
| GPU | Graphics Processing Unit |
| HTTP | Hypertext Transfer Protocol |
| IFC | Information Flow Control |
| IFC-001 | Confidentiality taint gate (high-to-low flow) |
| IFC-002 | Integrity taint gate (untrusted-to-action flow) |
| JSON | JavaScript Object Notation |
| JSON-RPC | JSON Remote Procedure Call |
| LLM | Large Language Model |
| LOC | Lines of Code |
| MCP | Model Context Protocol |
| OWASP | Open Worldwide Application Security Project |
| PII | Personally Identifiable Information |
| ReAct | Reason and Act (agent loop pattern) |
| SAMOS | The information-flow policy model used in this project |
| SRS | Software Requirements Specification |
| TCO | Total Cost of Ownership |
| UML | Unified Modeling Language |
| VRAM | Video Random Access Memory |
| YAML | YAML Ain't Markup Language |
