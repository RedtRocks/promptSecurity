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
the same enforcement gates. Across a ten-tool corpus over five independent runs, the synthesised policies blocked 87%
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
