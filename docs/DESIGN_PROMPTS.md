# Claude Design Prompts — SecureAgent Deck

Paste each block separately. Every slide prompt is self-contained — Claude Design remembers
nothing between them, so the visual system is restated in one line each time.

**Order note:** the two hardest slides (architecture, progress chart) come first so you can
iterate on them while you still have patience. Slides 1–5 and 7–13, 15 follow in deck order
afterwards.

---

## DECK-LEVEL PROMPT — the visual system

```
Define a visual system for a 15-slide academic capstone presentation on AI agent security.
16:9, 1920x1080. The subject is adversarial security research — the deck should feel like a
security research talk, not a startup pitch and not a default university template.

PALETTE — use these exact hex values, named:
- Ink (primary text, headlines):        #14161A
- Slate (body text, secondary):         #4A5160
- Signal (primary accent, emphasis):    #1F5F8B   deep instrument blue
- Ember (secondary accent, attacks):    #C1543A   burnt orange-red
- Paper (page background):              #FAF9F6   warm off-white
- Rule (borders, gridlines, dividers):  #D8D5CE

SEMANTIC COLOURS — used only in the progress chart and status indicators:
- Done:        #2E7D5B   deep green
- In progress: #C08A2E   amber
- Planned:     #8C93A1   neutral grey

Do not use pure white (#FFFFFF) or pure black (#000000) anywhere. Paper and Ink replace them.
Avoid generic corporate blue gradients, glossy 3D effects, and drop shadows on text.

TYPE:
- Headline: 44pt, semibold, Ink, sentence case, max two lines, left-aligned
- Sub-headline / eyebrow: 18pt, medium, Signal, uppercase, letter-spaced 0.08em
- Body and bullets: 22pt, regular, Slate, left-aligned, never centred
- Table text: 17pt, regular; table headers 17pt semibold, Ink
- Caption and source notes: 14pt, regular, Slate at 70% opacity
- Code and identifiers: monospace, 18pt, Ink, on a #F0EEE8 tint with 4px radius, no border

GRID:
- Margins: 80px left and right, 64px top, 72px bottom
- 12-column grid, 24px gutters
- Slide number bottom-right, 14pt, Rule colour
- A 2px Signal rule under every headline, spanning the content width, 20px below the baseline
- Never centre body content vertically; content starts below the headline rule and flows down

DIAGRAMS:
- Boxes: 1.5px Rule border, Paper fill, 6px corner radius, 18pt Ink label
- Emphasised boxes (the thing being discussed): 2px Signal border, #EAF1F6 fill
- Danger or attack boxes: 2px Ember border, #FBEEEA fill
- Safe or blocked-successfully boxes: 2px Done border, #E9F2ED fill
- Arrows: 1.5px Slate, solid for data flow, dashed for include or reference relationships
- Arrow labels: 15pt, Slate, on a Paper-filled chip so the line does not run through text
- No icon libraries, no clipart, no isometric illustration

CHARTS:
- No chart junk: no 3D, no gradients, no drop shadows, no background fill on plot areas
- Horizontal gridlines only, 1px Rule, no vertical gridlines, no chart border
- Bars: flat fill, 2px gap-to-width ratio of roughly 0.4
- Data labels printed directly on or beside bars — no legend when two series can be labelled
- Axis labels 15pt Slate; axis titles 16pt Slate; no axis line on the value axis

CODE BLOCKS:
- #F0EEE8 background, 6px radius, 20px padding, no border
- 18pt monospace, Ink; comments in Slate italic
- A 3px Signal bar down the left edge
- Never syntax-highlight in more than two colours

Tone: precise, quiet, evidence-forward. Whitespace is a feature. If a slide looks sparse,
it is correct.
```

---

## Slide 6 — System architecture

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM (apply exactly): Paper background #FAF9F6; Ink #14161A headlines 44pt
semibold sentence case; Slate #4A5160 body 22pt; Signal accent #1F5F8B; Ember #C1543A for
attack elements; Rule #D8D5CE borders; 80px side margins, 64px top; 2px Signal rule under
the headline; slide number bottom-right 14pt. No pure white or black. No shadows, no
gradients, no icons.

LAYOUT: Left third — headline and five bullets. Right two thirds — the architecture diagram,
vertically centred within the content area.

HEADLINE (verbatim):
Attack, analyse, synthesise, enforce

BULLETS (verbatim, 22pt Slate, no bullet glyphs — use 2px Signal 12px-wide dashes):
- Stage 1 attacks a live agent, escalates on refusal
- Stage 2 classifies why each attack worked
- Stage 3 compiles findings into an enforceable policy
- Verifier replays trajectories — no model in the loop
- Gateway enforces the policy at runtime

DIAGRAM — render this Mermaid, styled per the visual system:

flowchart LR
    A["tool.yaml"] --> B["Stage 1<br/>Red Agent"]
    B <-->|"attacks /<br/>trajectories"| C["Live agent<br/>ReAct loop"]
    B --> D["Stage 2<br/>exploit type A–E"]
    D --> E["Stage 3<br/>SAMOS policy"]
    E --> F["Verifier<br/>deterministic<br/>ABR · BPR · F1"]
    E --> G["Gateway<br/>runtime<br/>enforcement"]

DIAGRAM STYLING:
- "Stage 1 Red Agent" box: Ember border #C1543A, fill #FBEEEA — it is the adversarial stage
- "Verifier" box: Signal border #1F5F8B, fill #EAF1F6 — it is the emphasised contribution
- "Gateway" box: Done border #2E7D5B, fill #E9F2ED — it is the deployed artifact
- All other boxes: Rule border, Paper fill
- The bidirectional arrow between Stage 1 and Live agent must be visibly double-headed
- Arrow labels on Paper-filled chips at 15pt so lines do not strike through text
- Add a 14pt Slate caption below the diagram: "No language model is consulted in the verifier."

DO NOT INCLUDE: cloud icons, server-rack clipart, robot or brain imagery, an isometric
perspective, a gradient background, a "Powered by AI" badge, or arrows that cross each other.
Do not add a legend — the three coloured boxes are explained by the caption and the bullets.
```

---

## Slide 14 — Progress chart

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM (apply exactly): Paper background #FAF9F6; Ink #14161A headline 44pt semibold
sentence case; Slate #4A5160 body 22pt; Signal #1F5F8B; Rule #D8D5CE; 80px side margins,
64px top; 2px Signal rule under the headline; slide number bottom-right 14pt. No pure white
or black, no shadows, no gradients.

LAYOUT: Headline across the full width. Below it, a horizontal bar chart occupying the left
two thirds. Right third — a stacked summary block, top-aligned with the chart.

HEADLINE (verbatim):
Five of six deliverables above sixty percent

CHART — horizontal bars, one per row, value axis 0 to 100:

deliverable            percent   status
O1 Red Agent              85     in-progress
O2 Defender Agent         90     in-progress
O3a Enforcement          100     done
O3b Verification          60     in-progress
O4a Intent layer           0     planned
O4b Dashboard             60     in-progress

BAR COLOURS BY STATUS:
- done        #2E7D5B
- in-progress #C08A2E
- planned     #8C93A1

CHART RULES:
- Print the percentage as a data label immediately right of each bar end, 18pt semibold Ink
- The "O4a Intent layer" row has value 0 — render it as a 3px Planned-coloured stub at the
  axis with the label "0%" beside it, so the row is visibly present rather than blank
- Vertical gridlines at 25/50/75/100 only, 1px Rule; no plot border; no vertical axis line
- Category labels 18pt Ink, left-aligned, in a fixed-width column
- Small legend below the chart, 15pt: three swatches — Complete / In progress / Planned

RIGHT-HAND SUMMARY BLOCK:
- "71%" in 96pt semibold Signal
- Beneath it, 20pt Slate: "weighted completion across four approved objectives"
- A 1px Rule divider
- Then exactly three lines, 18pt Slate, each preceded by a 10px status swatch in the matching
  semantic colour:
    "1 complete"        (swatch #2E7D5B)
    "4 in progress"     (swatch #C08A2E)
    "1 not started"     (swatch #8C93A1)
  These sum to the six bars in the chart. Do not add a fourth line.

WHAT THE READER SHOULD CONCLUDE: the project is substantially built, and the shortfall is
concentrated in one deliverable that was deliberately replaced rather than left undone.

DO NOT INCLUDE: a pie chart, a donut, percentage-complete rings, traffic-light icons, a
progress bar metaphor with a runner or rocket, 3D bars, gradient bar fills, or a "we are
here" marker. Do not sort the bars by value — keep the objective order O1, O2, O3a, O3b,
O4a, O4b so the numbering reads sequentially.
```

---

## Slide 1 — Title

```
Create a 16:9 title slide, 1920x1080, for an academic capstone presentation.

VISUAL SYSTEM: Paper background #FAF9F6; Ink #14161A; Slate #4A5160; Signal #1F5F8B;
Rule #D8D5CE; 80px side margins. No pure white or black, no shadows, no gradients.

LAYOUT: Left-aligned, content occupying the left two thirds, vertically positioned in the
upper-middle. Right third left empty except for a single 2px Signal vertical rule running
the full content height, 120px from the right margin.

CONTENT (verbatim):

Eyebrow, 18pt Signal uppercase letter-spaced:
CAPSTONE PROJECT · MID SEMESTER EVALUATION · AUGUST 2026

Title, 80pt semibold Ink:
SecureAgent

Subtitle, 30pt regular Slate:
Adversarial attack surface analysis for AI agent tools

Then a 1px Rule divider at 60% width.

Team block, 19pt Slate, two columns:
Aarav Dudeja — 102303179
Akshat Srivastava — 102303904
Hiten Yadav — 102306026
Sanil Grover — 102317215
Simran Arora — 102306046

Below, 18pt Slate:
BE Fourth Year, COE/CSE · CPG No. 215

Mentor block, 18pt Slate:
Mentor: Dr. Gurpal Singh Chhabra, Assistant Professor, CSE
Co-Mentor: Dr. Amit Kumar Trivedi, Assistant Professor, CSE

Footer, 16pt Slate 70% opacity:
Computer Science and Engineering Department
Thapar Institute of Engineering and Technology, Patiala

DO NOT INCLUDE: a stock photograph of a padlock, a shield icon, binary-code or matrix
backgrounds, a hooded-figure hacker image, circuit-board texture, a glowing brain, or a
university crest scaled larger than 100px. Do not centre the text. Do not add a tagline.
```

---

## Slide 2 — Problem definition

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold sentence case; Slate
#4A5160 body 22pt; Signal #1F5F8B; Ember #C1543A for hostile elements; Rule #D8D5CE; 80px
margins; 2px Signal rule under headline; slide number bottom-right. No shadows or gradients.

LAYOUT: Headline full width. Below, diagram across the upper two thirds of the content area,
bullets in a single row of five short columns beneath it — or, if that is cramped, bullets
left half and diagram right half.

HEADLINE (verbatim):
The tool description is an unauthenticated instruction channel

BULLETS (verbatim):
- Agents now read files, send mail, run commands
- MCP tool descriptions come from third parties
- Agents read those descriptions as trusted instructions
- Nothing verifies the description is honest
- OWASP names this MCP03:2025 Tool Poisoning

DIAGRAM — render this Mermaid:

flowchart LR
    A["Third-party<br/>MCP server"] -->|"tool description<br/>attacker-controlled"| B["Agent"]
    B --> C["Real actions:<br/>files · email · shell"]

STYLING:
- "Third-party MCP server" box: Ember border, #FBEEEA fill
- "Real actions" box: Ember border, #FBEEEA fill
- "Agent" box: Rule border, Paper fill, drawn larger than the others
- The arrow from server to agent: 2.5px Ember, and its label set in Ember semibold
- Add a small self-referential loop arrow on the Agent box labelled "reads as trusted",
  1.5px Slate
- Caption below, 14pt Slate: "The trust boundary is in the wrong place."

WHAT THE READER SHOULD CONCLUDE: untrusted text controls a system with real-world side
effects, and no mechanism checks it.

DO NOT INCLUDE: a red warning triangle, a skull, a bug icon, a firewall-brick-wall graphic,
lock icons, or an "attacker in a hoodie" figure. Do not animate. Do not add a second
diagram.
```

---

## Slide 3 — Scope and approved objectives

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160; Signal
#1F5F8B; Rule #D8D5CE; semantic colours Done #2E7D5B, In-progress #C08A2E, Planned #8C93A1;
80px margins; 2px Signal rule under headline; table text 17pt, headers 17pt semibold Ink.
No shadows or gradients.

LAYOUT: Headline full width. Table occupying the full content width beneath it, vertically
centred in the remaining space.

HEADLINE (verbatim):
Four approved objectives, one substituted

TABLE (verbatim content):

#     Objective (abbreviated)                        Status
O1    Red Agent — schema-aware adversarial attacks   85%
O2    Defender Agent — analyse, synthesise policy    90%
O3    Enforcement engine + verification loop         80%
O4    Intent alignment layer + security dashboard    30%
      Weighted completion                            71%

TABLE STYLING:
- Header row: 1.5px Ink rule beneath, no fill, no vertical borders anywhere
- Body rows: 1px Rule divider between rows, generous 20px vertical cell padding
- Final row ("Weighted completion / 71%"): 1.5px Ink rule above it, text semibold Ink,
  and the "71%" rendered at 32pt semibold Signal
- Status column right-aligned; add a 6px-wide vertical status bar at the left edge of each
  status cell coloured: O1 amber, O2 amber, O3 amber, O4 grey
- The O4 row: set its objective text in Slate with the words "Intent alignment layer"
  in Ember, signalling the substituted component

WHAT THE READER SHOULD CONCLUDE: three objectives are nearly done, the fourth is the gap,
and the presenter is about to explain why.

DO NOT INCLUDE: checkmark or cross icons, traffic-light circles, a completion ring, emoji,
zebra striping on table rows, or vertical table borders. Do not colour whole rows.
```

---

## Slide 4 — Literature comparison

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold sentence case; Slate
#4A5160; Signal #1F5F8B; Ember #C1543A; Rule #D8D5CE; 80px margins; 2px Signal rule under
headline; table text 16pt, headers 16pt semibold Ink. No shadows or gradients.

LAYOUT: Headline full width, then a six-row four-column table filling the content area. This
slide is dense by design — keep 16px vertical cell padding and let it breathe horizontally.

HEADLINE (verbatim):
Existing defenses are cheap-and-weak or strong-and-intrusive

TABLE (verbatim):

Work              Approach                        Result                     Limitation
AgentDojo [8]     Attack/defense benchmark        97 tasks, 629 cases        Evaluates, ships no defense
ASB [10]          Broad benchmark                 ASR up to 84.3%            No deployable artifact
MCPTox [21]       Poisoning on real servers       ASR 72.8%, refusal <3%     Attack-side only
Spotlighting [11] Mark untrusted input            >50% → <2%                 Fails once model complies
CaMeL [16]        Flow extraction + capabilities  77% solved, provable       Requires agent rewrite
Progent [26]      Symbolic privilege policies     Lower ASR, utility held    Policy from trusted task

STYLING:
- Header row: 1.5px Ink rule beneath; no vertical borders; no row striping
- Bracketed citation numbers in Signal, the work name in semibold Ink
- The "Result" column values in semibold Ink so the numbers read first
- The "Limitation" column in Slate at 90% opacity — it is the argument, but secondary
- Give the CaMeL row a 3px Signal bar at its left edge and a 14pt Signal note beneath the
  table: "CaMeL is the closest prior art. We do not claim to beat it on security."

WHAT THE READER SHOULD CONCLUDE: the field measures the problem well and defends it either
cheaply-and-conditionally or strongly-and-invasively, with nothing in between.

DO NOT INCLUDE: logos of the cited projects, a scatter plot, star ratings, thumbs up/down
icons, or a "winner" highlight on any row. Do not abbreviate the limitation column further.
```

---

## Slide 5 — Research gap and positioning

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 22pt;
Signal #1F5F8B; Ember #C1543A; Rule #D8D5CE; 80px margins; 2px Signal rule under headline.
No shadows or gradients.

LAYOUT: Left 45% — headline and five bullets. Right 55% — a 2x2 positioning quadrant chart.

HEADLINE (verbatim):
Per-tool policy for an agent nobody rewrote

BULLETS (verbatim):
- Benchmarks evaluate; they emit no control
- Prompt defenses fail once the model complies
- System defenses demand a new agent runtime
- We synthesise policy per tool, enforce at dispatch
- We do not claim to beat CaMeL on security

QUADRANT CHART:
- X axis, left to right: "Low adoption cost" → "High adoption cost"
- Y axis, bottom to top: "Model-dependent" → "Model-independent"
- Plot these points at these normalised positions (x, y):
    Spotlighting        (0.15, 0.20)
    StruQ / SecAlign    (0.55, 0.30)
    CaMeL               (0.85, 0.90)
    IsolateGPT          (0.80, 0.75)
    SecureAgent         (0.25, 0.80)

CHART STYLING:
- 1px Rule axes with a single 1px Rule cross dividing the quadrants; no quadrant fills
  except a very light #EAF1F6 wash on the upper-left quadrant only
- Prior-work points: 10px filled circles in Slate, labels 17pt Slate
- The "SecureAgent" point: 16px filled circle in Signal, label 19pt semibold Signal
- Label the upper-left quadrant "Model-independent, low cost" in 15pt Signal at 70% opacity
- No gridlines, no numeric tick labels — the axes are qualitative

WHAT THE READER SHOULD CONCLUDE: the upper-left region is empty in the literature, and that
is precisely where this project sits — not because it is stronger, but because it is cheaper
to adopt while remaining independent of model behaviour.

DO NOT INCLUDE: a magic-quadrant styling with vendor-analyst branding, arrows pointing at
"us", a "gap" starburst, competitor logos, or a fifth axis. Do not shade three quadrants.
```

---

## Slide 7 — UML: use case and sequence

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160; Signal
#1F5F8B; Ember #C1543A; Rule #D8D5CE; 80px margins; 2px Signal rule under headline; diagram
box labels 17pt. No shadows or gradients, no icon libraries.

LAYOUT: Headline full width. Content area split into two equal columns with a 1px Rule
vertical divider between them. Left column titled "Actors and use cases" (18pt Signal
uppercase eyebrow); right column titled "Attack cycle" (same treatment).

HEADLINE (verbatim):
A refusal escalates instead of ending the search

LEFT DIAGRAM — render this Mermaid:

flowchart LR
    SEC(["Security<br/>Reviewer"]) --> UC1["Analyse tool"]
    DEV(["Integrator"]) --> UC2["Harden tool"]
    OPS(["Operator"]) --> UC3["Deploy gateway"]
    UC2 -.->|"include"| UC1
    UC3 -.->|"include"| UC4["Audit decisions"]

RIGHT DIAGRAM — render this Mermaid:

sequenceDiagram
    participant R as Refiner
    participant A as Agent
    participant G as Grader
    R->>A: adversarial prompt
    A-->>R: trajectory
    R->>G: grade
    G-->>R: score
    alt refused
        R->>R: escalate strategy
    else failed
        R->>R: diagnose, rewrite
    end

STYLING:
- Actor shapes: stadium outlines, 1.5px Slate, Paper fill
- Use case boxes: Rule border, Paper fill; "include" arrows dashed 1.5px Slate
- Sequence diagram: lifelines 1px Rule dashed; solid 1.5px arrows for calls, dashed for
  returns; the "alt / else" block drawn as a 1.5px Signal-bordered frame with the condition
  labels in 15pt Signal
- The "escalate strategy" self-message: 2px Ember with its label in Ember semibold — this is
  the mechanism the headline claims
- Caption beneath the right diagram, 14pt Slate: "Refusal and ineffectiveness are handled
  differently — conflating them wastes the refinement budget."

DO NOT INCLUDE: stick-figure clipart for actors, UML stereotype guillemets rendered as
double angle brackets that break the font, a third diagram, colour-coded lifelines, or
numbered step badges.
```

---

## Slide 8 — Data design

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 22pt;
Signal #1F5F8B; Rule #D8D5CE; monospace identifiers 18pt on #F0EEE8 with 4px radius; 80px
margins; 2px Signal rule under headline. No shadows or gradients.

LAYOUT: Headline full width. Diagram as a horizontal chain across the upper 60% of the
content area. Four bullets in a single row of four columns beneath it.

HEADLINE (verbatim):
Every stage boundary is a validated contract

DIAGRAM — render this Mermaid as a left-to-right chain:

flowchart LR
    A["MCPToolDefinition"] --> B["ToolProfile"]
    B --> C["AdversarialPrompt"]
    C --> D["AgentTrajectory"]
    D --> E["AttackRecord"]
    E --> F["VulnerabilityFinding"]
    F --> G["SAMOSPolicy"]
    E --> H["VerifierVerdict"]
    G --> H
    H --> I["SecurityUtilityReport"]

BULLETS (verbatim):
- Pydantic v2 models — no untyped dicts cross stages
- Malformed payloads fail at the boundary, not later
- No database: JSON and YAML artifacts on disk
- Policy carries a measurement of itself

STYLING:
- All contract boxes: Rule border, Paper fill, label in 17pt monospace Ink
- "SAMOSPolicy" and "VerifierVerdict" boxes: Signal border, #EAF1F6 fill — these are the
  contribution
- Route the two converging arrows into "VerifierVerdict" so they do not overlap; the
  AttackRecord→VerifierVerdict and SAMOSPolicy→VerifierVerdict arrows should approach from
  visibly different angles
- Caption below the diagram, 14pt Slate: "The policy is evaluated against the same records
  it was built from."

WHAT THE READER SHOULD CONCLUDE: this is a linear, typed transformation chain with one
deliberate feedback point — the measurement step.

DO NOT INCLUDE: a database cylinder icon (there is no database), ER crow's-feet notation,
class-diagram compartments with field lists, colour-coded data types, or a legend.
```

---

## Slide 9 — Tools and platforms

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160; Signal
#1F5F8B; Rule #D8D5CE; table text 18pt, headers 18pt semibold Ink; monospace names 18pt on
#F0EEE8. 80px margins; 2px Signal rule under headline. No shadows or gradients.

LAYOUT: Headline full width, then a two-column six-row table filling the content area with
generous row padding.

HEADLINE (verbatim):
Every choice bought a specific property

TABLE (verbatim):

Technology            Why this one
Pydantic v2           Contracts enforced at runtime, not documented
LiteLLM               One abstraction over three providers with retry
Ollama, direct HTTP   Router can't express think:false + JSON mode
FastAPI               Both servers are small validated JSON APIs
Jinja2 + Chart.js     Self-contained report, no build step, opens offline
pytest                196 tests incl. corpus/benign-suite invariants

STYLING:
- Technology column: 30% width, names set in monospace on the #F0EEE8 tint
- Reason column: 70% width, Slate, 18pt
- Header row 1.5px Ink rule beneath; 1px Rule dividers between rows; no vertical borders
- The literal "think:false" rendered in monospace inline within its sentence
- Numbers ("three", "196") set in semibold Ink

WHAT THE READER SHOULD CONCLUDE: the stack was chosen for specific properties, not defaults
— including one deliberate bypass of the abstraction layer.

DO NOT INCLUDE: technology logos of any kind, a layered "tech stack" pyramid or wedding-cake
graphic, version-number badges, star ratings, or a "why we chose X over Y" comparison column.
```

---

## Slide 10 — UI and component design

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 20pt;
Signal #1F5F8B; Rule #D8D5CE; 80px margins; 2px Signal rule under headline. No shadows,
except screenshots may carry a 1px Rule border. No gradients.

LAYOUT: Headline full width. Two screenshot placeholders side by side across the upper two
thirds, each with a 15pt Slate caption beneath. Five bullets in two columns at the bottom.

HEADLINE (verbatim):
Every number is auditable, not just reported

IMAGE PLACEHOLDERS — leave two empty framed regions, each 1px Rule border, #F0EEE8 fill,
with the placeholder text centred in 16pt Slate:
- Left, landscape 16:10: "slide10_terminal.png — live attack table"
- Right, landscape 16:10: "slide10_dashboard.png — report ABR / BPR / F1"

CAPTIONS (15pt Slate, beneath each frame):
- Left: "Live run — objective, technique, attempt, score"
- Right: "Report — risk scores, policy, per-record verdicts"

BULLETS (verbatim, two columns):
- Live terminal table: objective, technique, attempt, score
- HTML report: risk scores, policy, findings, verdicts
- Per-record verdict table — audit any coverage figure
- Red banner if a deny-all policy is detected
- Gateway /audit exposes enforcement events

STYLING:
- Set "/audit" in monospace on the #F0EEE8 tint
- The bullet mentioning the red banner: set the words "Red banner" in Ember

WHAT THE READER SHOULD CONCLUDE: the system reports numbers a reviewer can independently
check, rather than asking to be trusted.

DO NOT INCLUDE: mock browser chrome with fake traffic-light buttons, a laptop or phone
device frame around the screenshots, a cursor graphic, annotation arrows with circles, or
filler lorem-ipsum inside the placeholders.
```

---

## Slide 11 — Prototype: working today

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 20pt;
Signal #1F5F8B; Ember #C1543A; Rule #D8D5CE; 80px margins; 2px Signal rule under headline.
Charts: horizontal gridlines only, no 3D, no gradients, no plot border.

LAYOUT: Headline full width. Grouped bar chart occupying the left 70%. Four bullets stacked
in the right 30%, top-aligned with the chart.

HEADLINE (verbatim):
Utility holds at 0.94 across ten tools

CHART — grouped horizontal bars, two series per tool, value axis 0.0 to 1.0:

tool              ABR    BPR
list_directory    0.75   1.00
database_query    0.65   0.89
execute_command   0.47   1.00
write_file        0.56   1.00
read_file         0.33   1.00
send_email        0.50   0.67
web_search        0.17   1.00
manage_calendar   0.11   0.89
post_message      0.07   1.00
http_request      0.00   1.00

SERIES COLOURS:
- BPR (benign pass rate, the utility side): Signal #1F5F8B
- ABR (attack block rate, the security side): Ember #C1543A

CHART RULES:
- Two bars per tool, BPR drawn above ABR within each group
- Data labels at each bar end, 15pt, in the bar's own colour
- Vertical gridlines at 0.25 / 0.50 / 0.75 / 1.00 only, 1px Rule
- Add a 2px dashed Signal reference line at x = 0.944 labelled "mean BPR 0.944" in 15pt Signal
- Small inline legend above the chart, 15pt: two swatches — "BPR — legitimate tasks allowed",
  "ABR — successful attacks blocked"

BULLETS (verbatim, right column, 20pt):
- 16,802 lines Python · 196 tests · 10-tool corpus
- Mean BPR 0.944 — no degenerate deny-all anywhere
- Security non-trivial on argument- and flow-based tools
- n = 3 runs; some std exceed ±0.5 — not final

STYLING: set the final bullet entirely in Ember — it is the caveat and must not be missed.

WHAT THE READER SHOULD CONCLUDE: the utility side of the tradeoff is robust and consistent;
the security side works but is not yet precisely quantified.

DO NOT INCLUDE: error bars (n=3 makes them misleading at this size — the caveat bullet
carries that instead), a trend line, a "target" zone shading, tool icons, sorting by ABR, or
a 3D or stacked bar treatment. Do not omit the http_request row despite its 0.00 value.
```

---

## Slide 12 — Demo handoff

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 22pt;
Signal #1F5F8B; Ember #C1543A; Done #2E7D5B; Rule #D8D5CE; 80px margins; 2px Signal rule
under headline. No shadows or gradients.

LAYOUT: Headline full width. Diagram centred across the middle 70% of the content area.
Four bullets in a single row beneath it.

HEADLINE (verbatim):
Same prompt, same agent, one policy apart

DIAGRAM — render this Mermaid:

flowchart LR
    P["Attack prompt"] --> A["Agent :8080<br/>no policy"]
    P --> G["Gateway :8090<br/>policy enforced"]
    A --> R1["Succeeds<br/>data exfiltrated"]
    G --> R2["Blocked<br/>enforcement_log"]
    B["Benign task"] --> G
    G --> R3["Passes<br/>log empty"]

STYLING:
- "Attack prompt" and "Benign task": Rule border, Paper fill
- "Agent :8080" box: Ember border, #FBEEEA fill — unprotected path
- "Gateway :8090" box: Signal border, #EAF1F6 fill
- "Succeeds / data exfiltrated": Ember border, #FBEEEA fill
- "Blocked" and "Passes": Done border #2E7D5B, #E9F2ED fill
- Port numbers and "enforcement_log" set in monospace
- Draw the two paths from "Attack prompt" so the divergence is visually obvious — one
  branching up-left to the agent, one down-right to the gateway

BULLETS (verbatim):
- Attack straight to the agent → succeeds, no refusal
- Same attack through the gateway → blocked, gate logged
- Benign task through the gateway → passes untouched
- Decision is deterministic — no model consulted

WHAT THE READER SHOULD CONCLUDE: the only variable between success and blocked is the
policy, and blocking did not cost legitimate use.

DO NOT INCLUDE: a "LIVE DEMO" starburst or badge, a play-button graphic, a countdown timer,
screenshots (this slide is the handoff, not the demo), or a shield icon over the gateway box.
```

---

## Slide 13 — Cost analysis

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 20pt;
Signal #1F5F8B; Rule #D8D5CE; 80px margins; 2px Signal rule under headline. Charts: no 3D,
no gradients, no plot border, horizontal or vertical gridlines only as specified.

LAYOUT: Headline full width. Horizontal bar chart across the left 60%. Four bullets in the
right 40%, top-aligned.

HEADLINE (verbatim):
Full evaluation protocol costs under two thousand rupees

CHART — horizontal bars, value axis 0 to 5000, labelled in INR:

scenario                total_inr   dominant cost
A — Owned GPU               786     Gateway hosting
C — Hybrid                 1612     Hosted grader
C-var — Rented GPU         3865     GPU rental
B — Hosted API only        4756     GPT-4o tokens

CHART RULES:
- Bars in Signal #1F5F8B, except the "C — Hybrid" bar which is Done #2E7D5B
- Data label at each bar end: the rupee amount, 18pt semibold Ink, formatted "₹786", "₹1,612"
- Beneath each category label, a 14pt Slate sub-label giving the dominant cost from the
  table above
- Vertical gridlines at 1000 / 2000 / 3000 / 4000 / 5000, 1px Rule; no plot border
- Add a 15pt Done-coloured annotation beside the Hybrid bar: "recommended"
- Keep the row order exactly as listed — ascending by cost, not by scenario letter

BULLETS (verbatim, right column):
- 50 runs = 10 tools × 5 repeats, plus 1 month hosting
- Hybrid recommended: removes self-grading objection
- Generation model choice dominates, not run count
- Agent's own reasoning = 56% of all model calls

WHAT THE READER SHOULD CONCLUDE: the research is cheap to run, and the recommended
configuration costs a third of the fully-hosted one while being methodologically stronger.

DO NOT INCLUDE: currency or coin icons, a pie chart of cost breakdown, a dollar-to-rupee
conversion widget, cloud-provider logos, a "savings" percentage badge, or a stacked bar
splitting each scenario into components.
```

---

## Slide 15 — Future work

```
Create a 16:9 slide, 1920x1080, for an academic security research deck.

VISUAL SYSTEM: Paper #FAF9F6; Ink #14161A headline 44pt semibold; Slate #4A5160 body 19pt;
Signal #1F5F8B; Ember #C1543A; Rule #D8D5CE; semantic colours Done #2E7D5B, In-progress
#C08A2E, Planned #8C93A1; 80px margins; 2px Signal rule under headline. No shadows or
gradients.

LAYOUT: Headline full width. Below it a two-track horizontal timeline occupying the full
content width — "Evidence" track on top, "Build" track beneath, separated by a 1px Rule.

HEADLINE (verbatim):
Most of what remains is evidence, not code

TIMELINE — weeks 1 to 7 along the x axis, tick labels "Week 1" … "Week 7", 15pt Slate.

EVIDENCE TRACK (bars in Signal #1F5F8B):
- "Adaptive attack + poisoning evaluations" — Week 1
- "Defense baselines vs spotlighting" — Week 2
- "Full corpus, n=5 seeded" — Weeks 2–3

BUILD TRACK (bars in In-progress #C08A2E, except as noted):
- "Intent Alignment Layer" — Weeks 3–6 — render this bar in Ember #C1543A
- "Live monitoring dashboard" — Weeks 4–7
- "PII category · integrity gate · auth" — Weeks 3–5

TIMELINE STYLING:
- Track labels "EVIDENCE" and "BUILD" at the left in 16pt Signal uppercase letter-spaced
- Bars 28px tall, 4px radius, task label set inside the bar in 16pt Paper-coloured text where
  the bar is wide enough, otherwise immediately to its right in Ink
- Light vertical week gridlines, 1px Rule
- Beneath the Evidence track, a 15pt Signal note: "All code written — never executed"
- Beneath the Intent Alignment Layer bar, a 15pt Ember note: "the only genuine new build"

WHAT THE READER SHOULD CONCLUDE: the shortfall is mostly unexecuted experiments that take a
week, plus one real construction item that the team consciously deferred.

DO NOT INCLUDE: a roadmap-with-milestone-flags metaphor, a rocket or runner icon, percentage
completion on the bars, dependency arrows between tasks, a "you are here" marker, or a
calendar graphic. Do not extend the timeline beyond Week 7.
```
