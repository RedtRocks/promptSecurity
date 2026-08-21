"""Assemble docs/report/*.md into CapstoneMidTermReport.docx per docs/FORMAT_SPEC.md.

Applies:
  - A4 portrait, margins 1" top/bottom/right, 1.5" left           (FORMAT_SPEC 1)
  - Times New Roman; 16pt bold chapters, 14pt bold headings,
    12pt body, 10pt table content and captions                    (FORMAT_SPEC 2)
  - 1.5 line spacing for body                                     (FORMAT_SPEC 3)
  - Page numbers bottom centre; roman front matter, arabic body   (FORMAT_SPEC 4)
  - TABLE n.m captions above tables, FIGURE n.m below figures     (FORMAT_SPEC 6)

Mermaid blocks cannot be rendered here (no renderer available); each becomes a
labelled placeholder frame naming the figure it belongs to, so the diagram can be
pasted in without hunting for its location.

Usage:  python scripts/build_report_docx.py
"""

from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

import argparse

_ROOT = Path(__file__).resolve().parents[1]
_args = argparse.ArgumentParser(description=__doc__)
_args.add_argument("--dir", default="docs/report",
                   help="Directory holding front_matter.md, ch*.md, appendix_*.md")
_args.add_argument("--out", default=None, help="Output .docx path")
_OPTS, _ = _args.parse_known_args()

REPORT_DIR = _ROOT / _OPTS.dir
OUT_PATH = (_ROOT / _OPTS.out) if _OPTS.out else (REPORT_DIR / "CapstoneMidTermReport.docx")

FONT = "Times New Roman"
BODY_PT = 12
CHAPTER_PT = 16
HEADING_PT = 14
SUBHEADING_PT = 13
TABLE_PT = 10
CAPTION_PT = 10
MONO_FONT = "Consolas"

FRONT_MATTER = "front_matter.md"
BODY_FILES = [
    "ch1_introduction.md",
    "ch2_requirement_analysis.md",
    "ch3_methodology_adopted.md",
    "ch4_design_specifications.md",
    "ch5_conclusions_future_scope.md",
    "appendix_a_references.md",
    "appendix_b_plagiarism.md",
]

CAPTION_RE = re.compile(r"^\*{0,2}(TABLE|FIGURE|LISTING)\s+([\dA-Z.]+):\s*(.*)$", re.I)
INLINE_RE = re.compile(r"(\*\*.+?\*\*|\*[^*]+?\*|`[^`]+?`)")


# --------------------------------------------------------------------------- #
# document-level setup
# --------------------------------------------------------------------------- #
def setup_base_styles(doc: Document) -> None:
    normal = doc.styles["Normal"]
    normal.font.name = FONT
    normal.font.size = Pt(BODY_PT)
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.get_or_add_rFonts()
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(attr), FONT)
    pf = normal.paragraph_format
    pf.line_spacing = 1.5
    pf.space_after = Pt(6)


def configure_section(section, *, numfmt: str, start: int | None) -> None:
    """A4 portrait, FORMAT_SPEC margins, and a bottom-centre page number."""
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.right_margin = Inches(1)
    section.left_margin = Inches(1.5)

    sect_pr = section._sectPr
    for tag in ("w:pgNumType",):
        for el in sect_pr.findall(qn(tag)):
            sect_pr.remove(el)
    pg = OxmlElement("w:pgNumType")
    pg.set(qn("w:fmt"), numfmt)
    if start is not None:
        pg.set(qn("w:start"), str(start))
    sect_pr.append(pg)

    footer = section.footer
    footer.is_linked_to_previous = False
    p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    p.text = ""
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.line_spacing = 1.0
    run = p.add_run()
    run.font.name = FONT
    run.font.size = Pt(BODY_PT)
    for kind, val in (("begin", None), ("instrText", "PAGE"), ("end", None)):
        el = OxmlElement(f"w:fld{kind.capitalize()}" if kind != "instrText" else "w:instrText")
        if kind == "instrText":
            el.set(qn("xml:space"), "preserve")
            el.text = " PAGE "
        else:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        run._r.append(el)


def add_bottom_rule(par) -> None:
    """Heavy horizontal rule beneath a chapter heading (FORMAT_SPEC 2)."""
    p_pr = par._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "18")
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), "000000")
    borders.append(bottom)
    p_pr.append(borders)


# --------------------------------------------------------------------------- #
# inline + block emitters
# --------------------------------------------------------------------------- #
def add_runs(par, text: str, *, size: int, bold: bool = False) -> None:
    """Render **bold**, *italic* and `code` spans."""
    for part in INLINE_RE.split(text):
        if not part:
            continue
        run = par.add_run()
        run.font.size = Pt(size)
        run.font.name = FONT
        run.bold = bold
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            run.text = part[2:-2]
            run.bold = True
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            run.text = part[1:-1]
            run.font.name = MONO_FONT
            run.font.size = Pt(size - 1)
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            run.text = part[1:-1]
            run.italic = True
        else:
            run.text = part


def add_chapter(doc: Document, text: str) -> None:
    doc.add_page_break()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p.paragraph_format.space_after = Pt(12)
    r = p.add_run(text.upper())
    r.bold = True
    r.font.size = Pt(CHAPTER_PT)
    r.font.name = FONT
    add_bottom_rule(p)


def add_heading(doc: Document, text: str, level: int) -> None:
    size = {2: HEADING_PT, 3: SUBHEADING_PT}.get(level, BODY_PT)
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    add_runs(p, text, size=size, bold=True)
    for run in p.runs:
        run.bold = True
        run.font.size = Pt(size)


def add_caption(doc: Document, text: str) -> None:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(8)
    add_runs(p, text, size=CAPTION_PT)
    for run in p.runs:
        run.font.size = Pt(CAPTION_PT)
        run.bold = True


def add_placeholder(doc: Document, label: str, detail: str) -> None:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(f"[ {label} ]\n{detail}")
    r.font.size = Pt(CAPTION_PT)
    r.font.name = FONT
    r.italic = True
    r.font.color.rgb = RGBColor(0x60, 0x60, 0x60)
    p_pr = p._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    for edge in ("top", "left", "bottom", "right"):
        e = OxmlElement(f"w:{edge}")
        e.set(qn("w:val"), "dashed")
        e.set(qn("w:sz"), "6")
        e.set(qn("w:space"), "6")
        e.set(qn("w:color"), "808080")
        borders.append(e)
    p_pr.append(borders)


def add_code(doc: Document, lines: list[str]) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.left_indent = Inches(0.25)
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(6)
    r = p.add_run("\n".join(lines))
    r.font.name = MONO_FONT
    r.font.size = Pt(9)


def add_table(doc: Document, rows: list[list[str]]) -> None:
    if not rows:
        return
    ncols = max(len(r) for r in rows)
    table = doc.add_table(rows=0, cols=ncols)
    table.style = "Table Grid"
    for i, row in enumerate(rows):
        cells = table.add_row().cells
        for j in range(ncols):
            text = row[j] if j < len(row) else ""
            cell = cells[j]
            cell.text = ""
            par = cell.paragraphs[0]
            par.paragraph_format.line_spacing = 1.0
            par.paragraph_format.space_after = Pt(2)
            add_runs(par, text, size=TABLE_PT, bold=(i == 0))
            for run in par.runs:
                run.font.size = Pt(TABLE_PT)
                if i == 0:
                    run.bold = True
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def parse_table_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


# --------------------------------------------------------------------------- #
# markdown walker
# --------------------------------------------------------------------------- #
def render_markdown(doc: Document, text: str, *, is_front: bool) -> None:
    lines = text.splitlines()
    i = 0
    pending_fig: str | None = None

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # fenced blocks
        if stripped.startswith("```"):
            lang = stripped[3:].strip().lower()
            j = i + 1
            block: list[str] = []
            while j < len(lines) and not lines[j].strip().startswith("```"):
                block.append(lines[j])
                j += 1
            if lang in {"mermaid", "gantt", "xychart-beta"} or (
                block and block[0].strip().split()[:1] in ([["flowchart"]], [["sequenceDiagram"]])
            ):
                detail = pending_fig or "diagram — paste rendered image here"
                add_placeholder(doc, "MERMAID DIAGRAM", detail)
            else:
                add_code(doc, block)
            i = j + 1
            continue

        # tables
        if stripped.startswith("|") and stripped.endswith("|"):
            rows = []
            j = i
            while j < len(lines) and lines[j].strip().startswith("|"):
                row = parse_table_row(lines[j])
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in row if c):
                    rows.append(row)
                j += 1
            add_table(doc, rows)
            i = j
            continue

        # headings
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped.lstrip("#").strip()
            if level == 1:
                if is_front:
                    add_heading(doc, title, 2)
                else:
                    add_chapter(doc, title)
            else:
                add_heading(doc, title, min(level, 3))
            i += 1
            continue

        # captions
        m = CAPTION_RE.match(stripped)
        if m:
            clean = stripped.strip("*")
            add_caption(doc, clean)
            if m.group(1).upper() == "FIGURE":
                pending_fig = clean
            i += 1
            continue

        # screenshot markers
        if stripped.startswith("`[SCREENSHOT:") or stripped.startswith("[SCREENSHOT:"):
            add_placeholder(doc, "SCREENSHOT REQUIRED", stripped.strip("`"))
            i += 1
            continue

        # horizontal rule -> page break in front matter
        if stripped in {"---", "***", "___"}:
            if is_front:
                doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
            i += 1
            continue

        # blockquote
        if stripped.startswith(">"):
            buf = []
            j = i
            while j < len(lines) and lines[j].strip().startswith(">"):
                buf.append(lines[j].strip().lstrip(">").strip())
                j += 1
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.35)
            p.paragraph_format.space_before = Pt(6)
            add_runs(p, " ".join(x for x in buf if x), size=BODY_PT)
            for run in p.runs:
                run.italic = True
            i = j
            continue

        # list items
        if re.match(r"^[-*]\s+|^\d+\.\s+", stripped):
            content = re.sub(r"^[-*]\s+|^\d+\.\s+", "", stripped)
            p = doc.add_paragraph(style="List Bullet")
            p.paragraph_format.line_spacing = 1.5
            p.paragraph_format.space_after = Pt(2)
            add_runs(p, content, size=BODY_PT)
            i += 1
            continue

        # paragraph (join wrapped lines)
        buf = [stripped]
        j = i + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if not nxt or nxt.startswith(("#", "|", ">", "```", "- ", "* ")):
                break
            if CAPTION_RE.match(nxt):
                break
            buf.append(nxt)
            j += 1
        p = doc.add_paragraph()
        add_runs(p, " ".join(buf), size=BODY_PT)
        i = j


def main() -> None:
    doc = Document()
    setup_base_styles(doc)

    # --- front matter: roman numerals ---
    configure_section(doc.sections[0], numfmt="lowerRoman", start=1)
    front = (REPORT_DIR / FRONT_MATTER).read_text(encoding="utf-8")
    render_markdown(doc, front, is_front=True)

    # --- body: arabic, restarting at 1 ---
    body_section = doc.add_section(WD_SECTION.NEW_PAGE)
    configure_section(body_section, numfmt="decimal", start=1)

    for name in BODY_FILES:
        path = REPORT_DIR / name
        if not path.exists():
            print(f"  ! missing {name}")
            continue
        render_markdown(doc, path.read_text(encoding="utf-8"), is_front=False)
        print(f"  + {name}")

    doc.save(OUT_PATH)
    print(f"\nWrote {OUT_PATH}")
    print(
        "\nOpen in Word and: (1) insert TOC/LoF/LoT fields at their placeholder pages,\n"
        "(2) paste rendered diagrams into the dashed MERMAID frames,\n"
        "(3) paste screenshots into the SCREENSHOT frames, (4) update all fields (Ctrl+A, F9)."
    )


if __name__ == "__main__":
    main()
