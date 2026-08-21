# Report Format Specification

Checkable specification for the Capstone Project Report (Mid Semester Evaluation).
Every row is a checkbox tagged with the source it was extracted from.

**Source labels**

| Label | Document |
|---|---|
| `[GUIDELINES]` | Report Format Guidelines |
| `[TEMPLATE]` | Technical Report Format (MID SEMESTER 2026) |
| `[IEEE]` | IEEE Referencing Style Sheet — University of Bath, LW/DS/HC May 2015, updated Aug 2017 |

Where the sources disagree, the item is marked **⚠ see CONFLICTS** and both
versions are reproduced at the end of this file. No winner has been chosen.

---

## 1. Page setup

- [ ] Print type: **single side, coloured** `[GUIDELINES]`
- [ ] Paper size: **A4** `[GUIDELINES]`
- [ ] Orientation: **portrait** `[GUIDELINES]`
- [ ] Margin — top: **1"** `[GUIDELINES]`
- [ ] Margin — bottom: **1"** `[GUIDELINES]`
- [ ] Margin — right: **1"** `[GUIDELINES]`
- [ ] Margin — left: **1.5"** (binding edge) `[GUIDELINES]`

## 2. Fonts

- [ ] Font family throughout: **Times New Roman** `[GUIDELINES]`
- [ ] Chapter names: **16 pt, bold** `[GUIDELINES]`
- [ ] Headings: **14 pt, bold** `[GUIDELINES]`
- [ ] Sub-headings: **no size stated** — guidelines give only "chapter names / headings / normal text"; the 2.2.1.1 (sub-sub-heading) level is unspecified **⚠ see CONFLICTS (g)** `[GUIDELINES]`
- [ ] Body / normal text: **12 pt** (weight not stated; regular implied) `[GUIDELINES]`
- [ ] Table content: **10 pt** `[GUIDELINES]`
- [ ] Table captions: **10 pt** `[GUIDELINES]`
- [ ] Figure captions: **10 pt** `[GUIDELINES]`
- [ ] Chapter heading rendering in body: **right-aligned, ALL CAPS** (e.g. `INTRODUCTION`), with a **heavy horizontal rule beneath** `[TEMPLATE]`
- [ ] Front-matter page headings use the **same treatment** as chapter headings (right-aligned ALL CAPS + rule) `[TEMPLATE]`

## 3. Line spacing

- [ ] Body text: **1.5 throughout** `[GUIDELINES]`
- [ ] Reference list entries: **single spacing, justified** **⚠ see CONFLICTS (d)** `[GUIDELINES]`
- [ ] Reference list begins **2 spaces below** the heading `[GUIDELINES]`
- [ ] Reference list: single-space within an entry, **double-space between entries** `[IEEE]`

## 4. Page numbering

- [ ] Position: **bottom centre** of page `[GUIDELINES]`
- [ ] Format string: **UNRESOLVED — the guideline sentence is truncated in the source and the format is genuinely absent.** Must be confirmed with the department. **⚠ see CONFLICTS (e)** `[GUIDELINES]`
- [ ] Front matter: **lower-case roman numerals** `[TEMPLATE]`
- [ ] Body: **arabic numerals, Chapter 1 (Introduction) starts at page 1** `[TEMPLATE]`
- [ ] Front-matter numerals **as physically printed** on each page: see §5 table. These **do not match** the numbers listed in the Table of Contents **⚠ see CONFLICTS (a)** `[TEMPLATE]`

## 5. Mandatory front matter (exact order)

Order below is the **physical page order in the template**. The "Printed no."
column is the roman numeral actually appearing at the foot of that page.

- [ ] **Cover / Title page** — see §5.1 for required lines `[TEMPLATE]`
- [ ] **ABSTRACT** — printed **ii** `[TEMPLATE]`
- [ ] **DECLARATION** — printed **iii** `[TEMPLATE]`
- [ ] **ACKNOWLEDGEMENT** — printed **iv** `[TEMPLATE]`
- [ ] **TABLE OF CONTENTS** — printed **v–vi** `[TEMPLATE]`
- [ ] **LIST OF TABLES** — printed **vii** `[TEMPLATE]`
- [ ] **LIST OF FIGURES** — printed **viii** `[TEMPLATE]`
- [ ] **LIST OF ABBREVIATIONS** — printed **ix** `[TEMPLATE]`

⚠ The ToC lists these pages in a **different order and with different numbers** —
see CONFLICTS (a) and (b).

### 5.1 Cover / Title page — required lines, in order `[TEMPLATE]`

- [ ] TITLE OF PROJECT
- [ ] "Capstone Project Report"
- [ ] "MID SEMESTER EVALUATION"
- [ ] "Submitted by:"
- [ ] Four lines of `(<University Roll Number>)NAME OF THE STUDENT`
- [ ] "BE Third Year, CoE/CoSE"
- [ ] "CPG No: _____"
- [ ] "Under the Mentorship of"
- [ ] Name of Faculty Mentor I + Designation
- [ ] Name of Faculty Mentor II (if any) + Designation
- [ ] TIET logo
- [ ] "Computer Science and Engineering Department"
- [ ] "Thapar Institute of Engineering and Technology, Patiala"
- [ ] "August 2026"

### 5.2 DECLARATION page — required content `[TEMPLATE]`

- [ ] Declaration text: "We hereby declare that the design principles and working prototype model of the project entitled `<Title of Project>` is an authentic record of our own work carried out in the Computer Science and Engineering Department, TIET, Patiala, under the guidance of `<Mentor Name>` and `<Co-Mentor Name>` during 6th semester (2024)."
- [ ] Date
- [ ] Table of **Roll No. | Name | Signature**
- [ ] "Counter Signed By:" — Faculty Mentor block and Co-Mentor block, each with Designation / CSED / TIET, Patiala

### 5.3 ACKNOWLEDGEMENT page `[TEMPLATE]`

- [ ] Acknowledgement text + Date
- [ ] Table of **Roll No. | Name | Signature**

### 5.4 List pages — required columns `[TEMPLATE]`

- [ ] LIST OF TABLES columns: **Table No. | Caption | Page No.**
- [ ] LIST OF FIGURES columns: **Figure No. | Caption | Page No.**
- [ ] LIST OF ABBREVIATIONS: **two columns — ABBR | expansion**

## 6. Tables and figures

- [ ] Table caption format: **`TABLE 1: Caption of Table 1`** — ALL-CAPS label, colon, caption text `[TEMPLATE]`
- [ ] Table caption placement: **ABOVE** the table `[TEMPLATE]`
- [ ] Figure caption format: **`FIGURE 1: Caption of Figure 1`** — ALL-CAPS label, colon, caption text `[TEMPLATE]`
- [ ] Figure caption placement: **BELOW** the figure `[TEMPLATE]`
- [ ] Numbering: consecutive, per the `TABLE n` / `FIGURE n` pattern shown `[TEMPLATE]`
- [ ] Caption font: **10 pt** `[GUIDELINES]`
- [ ] **Every table and figure number must be referred to in the running text.** Verbatim: "Do refer to figure/table numbers in the running text also." `[TEMPLATE]`
- [ ] **Diagrams must have a detailed explanation.** Verbatim: "Diagrams should have a detailed explanation." `[TEMPLATE]`
- [ ] Every table appears in LIST OF TABLES with its caption and page number `[TEMPLATE]`
- [ ] Every figure appears in LIST OF FIGURES with its caption and page number `[TEMPLATE]`

### 6.1 Prescribed table layouts `[TEMPLATE]`

- [ ] **§2.1.3 Literature Survey table** — columns: `S. No. | Roll Number | Name | Paper Title | Tools/Technology | Findings | Citation`; rows grouped per team member, **~6 papers each**
- [ ] **§3.1 Investigative Techniques table** — columns: `S. No. | Investigative Projects Techniques | Investigative Techniques Description | Investigative Projects Examples`; three rows: **Descriptive, Comparative, Experimental**. Caveat verbatim: "Do ask your mentors regarding these techniques before quoting anything"
- [ ] **§1.5 Assumptions and Constraints table** — columns: `S. No. | Sample Assumptions`

## 7. Referencing — IEEE numeric style

### 7.1 In-text citation rules `[IEEE]`

- [ ] Numeric style; numbers assigned **in order of first appearance**
- [ ] Citation number in **square brackets**, on the **same line as the text**
- [ ] Bracket placed **before any punctuation**, with a **space before the bracket**
- [ ] Once assigned, **the same number is re-used** for every subsequent citation of that source
- [ ] Page numbers required for **direct quotes or a specific part**: `[1, p. 3]`
- [ ] Multiple sources: `[3, 4, 15, 16]` **or** `[3], [4], [15], [16]`
- [ ] In **running text**, three or more authors may be abbreviated "et al." (e.g. "Fan, et al. [4]")
- [ ] In the **reference list**, always give all authors' names; "et al." is permitted **only when there are six or more authors**
- [ ] Numbered consecutively in square brackets throughout the text and collected in the reference list at the end `[GUIDELINES]`

Worked in-text examples `[IEEE]`:
- "... as shown by Brown [4], as previously stated."
- "The theory was first put forward in 1987 [1]."
- "For example, see [7]."
- "Several recent studies [3, 4, 15, 16] have suggested that..."

### 7.2 Reference list layout `[IEEE]`

- [ ] Section headed **References**, entries in **numeric order** **⚠ see CONFLICTS (f)**
- [ ] References **aligned left**
- [ ] **Single-space** each entry, **double-space** between entries
- [ ] Number at the **left margin** in square brackets; **indent the text** of entries

### 7.3 Full reference formats with worked examples `[IEEE]`

- [ ] **Book** — `[n] Author's initials. Author's Surname, Book Title, edition (if not first). Place of publication: Publisher, Year.`
  `[1] I.A. Glover and P.M. Grant, Digital Communications, 3rd ed. Harlow: Prentice Hall, 2009.`

- [ ] **Book chapter** — `[n] Initials. Surname, "Title of chapter in book," in Book Title, edition, Editor's initials. Editor's Surname, Ed. Place: Publisher, Year, page numbers.`
  `[2] C. W. Li and G. J. Wang, "MEMS manufacturing techniques for tissue scaffolding devices," in Mems for Biomedical Applications, S. Bhansali and A. Vasudev, Eds. Cambridge: Woodhead, 2012, pp. 192-217.`

- [ ] **Electronic book** — `[n] Initials. Surname. (Year, Month Day). Book Title (edition) [Type of medium]. Available: URL`
  `[3] W. Zeng, H. Yu, C. Lin. (2013, Dec 19). Multimedia Security Technologies for Digital Rights Management [Online]. Available: http://goo.gl/xQ6doi`
  Rule: if the e-book is a **direct equivalent of the print book** (e.g. PDF), reference it as a normal print book.

- [ ] **Journal article** — `[n] Initials. Surname, "Title of article," Title of journal abbreviated in italics, vol. number, issue number, page numbers, Abbreviated Month Year.`
  `[4] F. Yan, Y. Gu, Y. Wang, C. M. Wang, X. Y. Hu, H. X. Peng, et al., "Study on the interaction mechanism between laser and rock during perforation," Optics and Laser Technology, vol. 54, pp. 303-308, Dec 2013.`
  Notes: omit issue numbers when the journal does not use them; this example uses "et al." because there are **six or more** authors.

- [ ] **E-journal article** — PDF versions of journal articles are direct copies of print → **cite as print journals**. Otherwise:
  `[n] Initials. Surname. (Year, Month). "Title of article." Journal Title [type of medium]. volume number, issue number, page numbers if given. Available: URL`
  `[5] M. Semilof. (1996, July). "Driving commerce to the web-corporate intranets and the internet: lines blur". Communication Week [Online]. vol. 6, issue 19. Available: http://www.techweb.com/se/directlinkcgi?CWK19960715S0005`

- [ ] **Conference paper** — `[n] Initials. Surname, "Title of paper," in Name of Conference, Location, Year, pp. xxx.`
  `[6] S. Adachi, T. Horio, T. Suzuki. "Intense vacuum-ultraviolet single-order harmonic pulse by a deep-ultraviolet driving laser," in Conf. Lasers and Electro-Optics, San Jose, CA, 2012, pp. 2118-2120.`
  Standard conference-name abbreviations may be applied.

- [ ] **Report** — name and location of company/institution after author and title; report number and date at the end; volume number after the year if any.
  `[n] Initials. Surname, "Title of report," Abbreviated Name of Company., City of Company., State, Report number, year.`
  `[7] P. Diament and W. L. Luptakin, "V-line surface-wave radiation and scanning," Dept. Elect. Eng., Colombia Univ., New York, Sci Rep. 85, 1991.`

- [ ] **Patent** — `[n] Initials. Surname, "Title of patent," Country where patent is registered. Patent number, Abbrev of Month Day Year.`
  `[8] J. P. Wilkinson, "Nonlinear resonant circuit devices," U.S. Patent 3 624 125, July 16 1990.`
  Use the **issued date** if several dates are given.

- [ ] **Standard** — `[n] Title of Standard, Standard number, date.`
  `[9] Shunt power capacitors, IEEE standard 18-2012, 2013.`

- [ ] **Thesis / dissertation** — `[n] Initials. Surname, "Title of thesis," Designation type, Abbrev. Dept., Abbrev. Univ., City of Univ., State, Year.`
  `[10] J. O. Williams, "Narrow-band analyser," Ph.D. dissertation, Dept. Elect. Eng., Harvard Univ., Cambridge, MA, 1993.`

- [ ] **Datasheet** — `[n] Initials. Surname, "Title of Datasheet," Part datasheet, Publication date [Latest revision date].`
  `[11] Texas Instruments, "High speed CMOS logic analog multiplexers/demultiplexers," 74HC4051 datasheet, Nov. 1997 [Revised Sept. 2002].`

- [ ] **Online document** — if an online report / conference paper / standard / patent / thesis has an **identical print equivalent** (same format and pagination), reference it as the print version. If **e-only**, add the material type in square brackets (e.g. `[Online]`) after the document title — or after the document number if there is no title — and end with `Available: URL`.
  `[12] M.R. Brooks, "Musical toothbrush with adjustable neck and mirror," U.S Patent 326189 [Online], May 19 1992. Available: http://goo.gl/VU1WEk`

- [ ] **Website** — include as much key information as can be found; if there is no personal author use a **corporate author**, failing that **"Anon."** or the **site title**.
  `[n] Initials. Surname. (Year, Month. Day). Title of web page [Online]. Available: URL`
  `[13] BBC News. (2013, Nov. 11). Microwave signals turned into electrical power [Online]. Available: http://www.bbc.co.uk/news/technology-24897584`
  `[14] M. Holland. (2002). Guide to citing internet sources [Online]. Available: http://www.bournemouth.ac.uk/library/using/guide_to_citing_internet_sourc.html`

### 7.4 Journal title abbreviations `[IEEE]`

- [ ] IEEE journal name list: https://www.ieee.org/documents/trans_journal_names.pdf
- [ ] Non-IEEE abbreviations: http://www.bath.ac.uk/library/help/infoguides/abbreviations.html
- [ ] Word abbreviations (IEEE style manual): http://www.ieee.org/documents/style_manual.pdf
- [ ] Base reference for the whole style: https://www.ieee.org/documents/ieeecitationref.pdf

### 7.5 EndNote caution `[IEEE]`

- [ ] Several IEEE variants exist in EndNote (IEEE-Pervasive Comp, IEEE Micro, IEEE ACM Trans Network) — check departmental preference
- [ ] Check imported records for errors

---

## 8. Mandatory chapter / section structure

Verbatim outline; parenthetical text is an instruction and must be satisfied. `[TEMPLATE]`

- [ ] **1. Introduction** — starts **page 1**
  - [ ] 1.1 Project Overview — **3–4 pages**
  - [ ] 1.2 Need Analysis — **1 page**, mentioning the significance of the work
  - [ ] 1.3 Research Gaps — **identify and explain at least FIVE research gaps, with references**
  - [ ] 1.4 Problem Definition and Scope
  - [ ] 1.5 Assumptions and Constraints — table per §6.1
  - [ ] 1.6 Standards
  - [ ] 1.7 Approved Objectives — objectives approved in Proposal Evaluation by panel
  - [ ] 1.8 Methodology
  - [ ] 1.9 Project Outcomes and Deliverables
  - [ ] 1.10 Novelty of Work
- [ ] **2. Requirement Analysis**
  - [ ] 2.1 Literature Survey
    - [ ] 2.1.1 Theory Associated With Problem Area
    - [ ] 2.1.2 Existing Systems and Solutions
    - [ ] 2.1.3 Research Findings for Existing Literature — table per §6.1
    - [ ] 2.1.4 Problem Identified
    - [ ] 2.1.5 Survey of Tools and Technologies Used
  - [ ] 2.2 Software Requirement Specification
    - [ ] 2.2.1 Introduction — 2.2.1.1 Purpose / 2.2.1.2 Intended Audience and Reading Suggestions / 2.2.1.3 Project Scope
    - [ ] 2.2.2 Overall Description — 2.2.2.1 Product Perspective / 2.2.2.2 Product Features
    - [ ] 2.2.3 External Interface Requirements — 2.2.3.1 User Interfaces / 2.2.3.2 Hardware Interfaces / 2.2.3.3 Software Interfaces
    - [ ] 2.2.4 Other Non-functional Requirements — 2.2.4.1 Performance Requirements / 2.2.4.2 Safety Requirements / 2.2.4.3 Security Requirements
  - [ ] 2.3 Cost Analysis
  - [ ] 2.4 Risk Analysis
- [ ] **3. Methodology Adopted**
  - [ ] 3.1 Investigative Techniques — **justify the selected investigative technique for your project, 2–3 pages**; table per §6.1
  - [ ] 3.2 Proposed Solution — **2–3 pages**
  - [ ] 3.3 Work Breakdown Structure — along with a discussion on workable modules/products
  - [ ] 3.4 Tools and Technology
- [ ] **4. Design Specifications** — sub-sections may vary according to the applicability of diagrams for student projects
  - [ ] 4.1 System Architecture — e.g. Block Diagram / Technology Stack / MVC / Tier architecture, whichever suits the project
  - [ ] 4.2 Design Level Diagrams
  - [ ] 4.3 User Interface Diagrams
  - [ ] 4.4 Snapshots of Working Prototype — along with a step-by-step discussion of the working prototype
- [ ] **5. Conclusions and Future Scope**
  - [ ] 5.1 Work Accomplished — discussion w.r.t. the approved objectives
  - [ ] 5.2 Conclusions
  - [ ] 5.3 Environmental (/ Economic / Social) Benefits
  - [ ] 5.4 Future Work Plan
- [ ] **APPENDIX A: References**
- [ ] **APPENDIX B: Plagiarism Report**

### 8.1 Explicit page-length / count requirements (roll-up)

- [ ] 1.1 Project Overview — 3–4 pages `[TEMPLATE]`
- [ ] 1.2 Need Analysis — 1 page `[TEMPLATE]`
- [ ] 1.3 Research Gaps — **≥ 5 gaps, each with references** `[TEMPLATE]`
- [ ] 2.1.3 Literature Survey table — ~6 papers **per team member** `[TEMPLATE]`
- [ ] 3.1 Investigative Techniques — 2–3 pages `[TEMPLATE]`
- [ ] 3.2 Proposed Solution — 2–3 pages `[TEMPLATE]`

---

## CONFLICTS

Both versions are stated. **No winner has been selected** — each must be resolved
with the department before submission.

### (a) Front-matter page numbers: as printed vs. as listed in the ToC

| Page | Printed at foot of page `[TEMPLATE]` | Listed in TABLE OF CONTENTS `[TEMPLATE]` |
|---|---|---|
| ABSTRACT | **ii** | **i** |
| DECLARATION | **iii** | **ii** |
| ACKNOWLEDGEMENT | **iv** | **iii** |
| TABLE OF CONTENTS | **v–vi** | *(not listed)* |
| LIST OF TABLES | **vii** | **v** |
| LIST OF FIGURES | **viii** | **iv** |
| LIST OF ABBREVIATIONS | **ix** | **vi** |

The two schemes are offset and cannot both be correct. ⚠ Unresolved.

### (b) Ordering of LIST OF TABLES vs. LIST OF FIGURES

- **Physical page order** `[TEMPLATE]`: LIST OF **TABLES** (vii) → LIST OF **FIGURES** (viii)
- **ToC order** `[TEMPLATE]`: LIST OF **FIGURES** (iv) → LIST OF **TABLES** (v)

The same template presents the two lists in opposite orders. ⚠ Unresolved.

### (c) Template reference examples vs. IEEE style sheet

| Aspect | `[TEMPLATE]` REFERENCES page | `[IEEE]` style sheet |
|---|---|---|
| Online source | `Internet: www.iceengg.edu/staff.html, Oct. 25, 2000 [Nov. 29, 2003]` — i.e. `Internet: URL, date published [date accessed]` | `[Online]. Available: URL` with `(Year, Month. Day)` before the title; **no** accessed date |
| Volume/issue | `vol. 38(4)` | `vol. 38, no. 4` |
| Author-list terminator | **period** after the author list — `T. Anderson, L. Peterson, S. Shenker, J. Turner. "Overcoming..."` | **comma** after the author list — `I.A. Glover and P.M. Grant, Digital Communications...` |

Template examples in full:
- `[1] T. Anderson, L. Peterson, S. Shenker, J. Turner. "Overcoming the Internet impasse through virtualization." IEEE Computer, vol. 38(4), pp. 34-41, Jan. 26, 2005.`
- `[2] M. Duncan. "Engineering Concepts on Ice." Internet: www.iceengg.edu/staff.html, Oct. 25, 2000 [Nov. 29, 2003]`

⚠ Unresolved — the template's own examples do not conform to the supplied IEEE sheet.

### (d) Reference list spacing vs. global line spacing

- `[GUIDELINES]` item 6: line spacing is **1.5 throughout**.
- `[GUIDELINES]` item 10: the reference list "should be typed 2 spaces below the heading 'REFERENCES' in **single spacing** justified."
- `[IEEE]`: **single-space** each entry, **double-space** between entries.

"Throughout" and the single-spaced reference list are mutually exclusive; the IEEE
sheet adds a third rule (double-space *between* entries) that the guidelines omit.
⚠ Unresolved.

### (e) Page-numbering format string is truncated

- `[GUIDELINES]` item 7 reads: "Page Numbering: Bottom center of page in the format:" — **the format string itself is absent from the source document.**
- No other source specifies it.

Position (bottom centre) is certain; the format is **unknown and must be obtained
from the department**. ⚠ Unresolved.

### (f) Heading for the reference section

- `[GUIDELINES]`: the heading is **"REFERENCES"**, with the list typed 2 spaces below it.
- `[TEMPLATE]`: the section appears as **"APPENDIX A: References"** at the end of the outline.
- `[IEEE]`: "reference list should be given a section heading, e.g. **References**".

Three different renderings of the same section heading. ⚠ Unresolved.

### (g) No font size specified for sub-sub-headings

- `[GUIDELINES]` item 5 defines only three levels: **16 bold** (chapter names), **14 bold** (headings), **12** (normal text).
- `[TEMPLATE]` requires a **four-level** hierarchy: chapter (1) → section (1.1) → subsection (2.2.1) → sub-subsection (2.2.1.1).

The guidelines provide no size or weight for the 2.2.1 and 2.2.1.1 levels.
⚠ Unresolved.

---

## Unresolved items summary

| # | Item | Blocking? |
|---|---|---|
| (a) | Front-matter page numbers — printed vs. ToC | Yes — affects every front-matter page |
| (b) | LIST OF TABLES / FIGURES ordering | Yes — affects front-matter assembly |
| (c) | Template reference examples vs. IEEE sheet | Yes — affects every reference entry |
| (d) | Reference list spacing vs. 1.5 throughout | Yes |
| (e) | Page-numbering format string (truncated in source) | Yes — format genuinely unknown |
| (f) | "REFERENCES" vs. "APPENDIX A: References" | Yes |
| (g) | Sub-sub-heading font size unspecified | Yes — 2.2.1.x levels are mandatory |

## Source transcription notes

- `[TEMPLATE]` Table of Contents misprints the chapter column heading as **"CH APTER"** (spurious space). Reproduced here for fidelity; presumed a typo in the source.
- `[GUIDELINES]` item 7 is truncated mid-sentence in the source — see CONFLICTS (e).
