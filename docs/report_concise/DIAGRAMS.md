# Report Diagrams — Mermaid Source

Two diagrams go into Chapter 4. Render each to PNG, then paste into the matching
dashed frame in the .docx.

## How to render

**Option A — mermaid.live (easiest, no install).**
1. Open <https://mermaid.live>
2. Paste the code block below into the left pane.
3. Set a light theme (Actions → Config → `"theme": "neutral"`) so it prints well.
4. **Actions → PNG** → choose *3x* scale. A 1x export looks blurry in Word.
5. Paste into the .docx frame.

**Option B — command line (sharper, repeatable).**
```bash
npm install -g @mermaid-js/mermaid-cli
mmdc -i fig41.mmd -o fig41.png -t neutral -b white -s 3
mmdc -i fig42.mmd -o fig42.png -t neutral -b white -s 3
```
Save each code block below into `fig41.mmd` / `fig42.mmd` first (without the
surrounding markdown fence).

**Print settings that matter:** white background (`-b white`), `neutral` theme,
scale 3. The report is printed in colour, but the diagrams must still be legible
in greyscale, so the shading below relies on outline weight rather than hue.

---

## FIGURE 4.1 — System Architecture

Goes in **Chapter 4, section 4.1**, replacing `*[SCREENSHOT: block diagram]*`.

Shows the two operating modes sharing one policy. The point a reader should take
away: the policy is the only artefact that crosses from analysis to enforcement,
and the agent is untouched in both modes.

```mermaid
flowchart TB
    TOOL["Tool definition<br/>(name, description, parameter schema)"]

    subgraph ANALYSIS["ANALYSIS MODE — run once per tool"]
        direction TB
        S1["Stage 1 — Attack<br/>6 misuse categories x 8 techniques<br/>refine and escalate on refusal"]
        S2["Stage 2 — Analyse<br/>classify why each attack worked<br/>aggregate across attacks"]
        S3["Stage 3 — Synthesise policy<br/>capabilities, confidentiality,<br/>taint rules, enforcement rules"]
        S1 --> S2 --> S3
    end

    AGENT["Live agent under test<br/>(unmodified)"]
    S1 <-->|"adversarial prompt<br/>/ recorded trajectory"| AGENT

    POLICY[["SAMOS Policy"]]
    S3 --> POLICY

    subgraph MEASURE["MEASUREMENT — deterministic, no model consulted"]
        direction TB
        CHK["Policy checker<br/>replays recorded trajectories"]
        ATK["Attack traces<br/>→ ABR"]
        BEN["Legitimate-use traces<br/>→ BPR"]
        CHK --> ATK
        CHK --> BEN
    end
    POLICY --> CHK

    subgraph ENFORCE["ENFORCEMENT MODE — runs continuously"]
        direction TB
        GW["Policy gateway<br/>four gates applied to every trajectory"]
        AUDIT[("Audit log<br/>gate + rule per decision")]
        GW --> AUDIT
    end
    POLICY --> GW

    CALLER["Agent callers"] --> GW
    GW <--> AGENT2["Live agent in production<br/>(unmodified)"]

    classDef art fill:#fff,stroke:#333,stroke-width:3px
    classDef ext fill:#fff,stroke:#666,stroke-width:1px,stroke-dasharray:4 3
    class POLICY art
    class AGENT,AGENT2,CALLER ext
```

**Caption to keep:** *FIGURE 4.1: System architecture — analysis mode produces a
policy, enforcement mode applies it.*

---

## FIGURE 4.2 — The Four Enforcement Gates

Goes in **Chapter 4, section 4.2**, replacing `*[SCREENSHOT: gate flow diagram]*`.

Shows gate order and the taint state carried between calls. Two things a reader
should take away: the gates are ordered from unconditional to most specific, and
both taint gates test taint accumulated from *prior* calls, which is what stops a
tool blocking itself on its first use.

```mermaid
flowchart TB
    START(["Tool call arrives<br/>(step N of trajectory)"])

    G1{"GATE 1 — Capability<br/>Is this tool's capability<br/>denied by the policy?"}
    G2{"GATE 2 — Confidentiality<br/>Session already HIGH tainted<br/>AND this call writes to a<br/>low-confidentiality sink?"}
    G3{"GATE 3 — Integrity<br/>Session already carries<br/>attacker-controlled content<br/>AND this is a consequential action?"}
    G4{"GATE 4 — Enforcement rules<br/>Trigger matches tool name<br/>AND argument conditions?"}

    BLOCK["BLOCKED<br/>trajectory ends"]
    ALLOW(["ALLOWED<br/>proceed to step N+1"])
    OTHER["AUDIT or<br/>REQUIRE_CONFIRMATION<br/>recorded, replay continues"]

    START --> G1
    G1 -->|yes| BLOCK
    G1 -->|no| G2
    G2 -->|yes| BLOCK
    G2 -->|no| G3
    G3 -->|yes| BLOCK
    G3 -->|no| G4
    G4 -->|"BLOCK"| BLOCK
    G4 -->|"AUDIT /<br/>CONFIRM"| OTHER
    G4 -->|no match| ALLOW
    OTHER --> ALLOW

    STATE["SESSION STATE carried to step N+1<br/>• confidentiality taint — raised by a high-confidentiality read, monotonic<br/>• integrity taint — raised once a response carries untrusted content<br/>Both gates test taint from PRIOR calls only, so no tool blocks itself on first use."]
    ALLOW -.-> STATE
    STATE -.-> START

    classDef stop fill:#fff,stroke:#333,stroke-width:3px
    classDef note fill:#fff,stroke:#666,stroke-width:1px,stroke-dasharray:4 3
    class BLOCK stop
    class STATE note
```

**Caption to keep:** *FIGURE 4.2: The four enforcement gates in order, with the
taint state carried between calls.*

---

## Optional — pipeline overview for the slides

Not a numbered report figure. Useful on a single slide if you present.

```mermaid
flowchart LR
    A["Tool<br/>description"] --> B["Attack it"]
    B --> C["See what<br/>actually worked"]
    C --> D["Write a<br/>policy"]
    D --> E["Enforce it<br/>at runtime"]
    E --> F["Measure both:<br/>attacks blocked 0.87<br/>legitimate use kept 1.00"]
```
