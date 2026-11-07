"""Assemble a Report from Markdown sections (which may embed chart images as
base64 data URIs from `shared.reporting.charts`) and render it to Markdown,
a styled standalone HTML file, and a PDF (via WeasyPrint, HTML -> PDF).

Besides sections, a report can carry a headline scorecard (a 0-100 score
with a per-area breakdown) and a row of KPI tiles. Markdown renders both as
plain text and tables so the .md file stays readable anywhere; HTML and PDF
render them as a score ring, meters, and tiles above the table of contents.
"""
from __future__ import annotations

import datetime
import functools
import html
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import markdown as _markdown

# Severity and status colors. These match `charts.SEVERITY_FILL`, so a level
# is the same color in a chart as in a table label.
SEVERITY_COLORS = {
    "CRITICAL": "#d03b3b",
    "HIGH": "#ec835a",
    "MEDIUM": "#fab219",
    "LOW": "#2a78d6",
    "INFORMATIONAL": "#898781",
    "PASS": "#0ca30c",
}

TONES = ("neutral", "good", "warn", "bad")

PLUGIN_NAME = "aws-well-architected-and-analysis"


@functools.lru_cache(maxsize=1)
def plugin_version() -> str | None:
    """The plugin version from .claude-plugin/plugin.json, printed in each
    report's header so a reader can tell which release produced it."""
    manifest = Path(__file__).resolve().parents[2] / ".claude-plugin" / "plugin.json"
    try:
        return json.loads(manifest.read_text()).get("version")
    except (OSError, ValueError):  # pragma: no cover - the manifest ships with the plugin
        return None


def escape_text(value) -> str:
    """HTML-escape a plain-text report field (title, subtitle, meta value,
    section heading, KPI, or table cell).

    Report content routinely carries live AWS resource metadata -- bucket
    names, tags, IAM usernames, Well-Architected workload names -- which a
    limited-privilege principal can set to arbitrary text. The rendered
    HTML report is meant to be opened in a browser, so any such string
    reaching the page unescaped is a stored-XSS path. Escaping with
    `quote=False` is correct for every sink here: all of them are HTML
    *element content* (including `<title>`), never attribute values.
    """
    return html.escape(str(value), quote=False)


@dataclass
class Section:
    title: str
    body_md: str
    level: int = 2


@dataclass
class Kpi:
    """One headline number. `value` is display text ("12", "$4.2K", "87%");
    `tone` colors the tile's accent: neutral, good, warn, or bad."""

    label: str
    value: str
    note: str | None = None
    tone: str = "neutral"

    def __post_init__(self):
        if self.tone not in TONES:
            raise ValueError(f"tone must be one of {TONES}, not {self.tone!r}")


@dataclass
class ScoreArea:
    name: str
    score: int | None
    detail: str = ""


@dataclass
class Scorecard:
    """A headline 0-100 score with a word band ("Fair"), a one-line detail
    ("31 of 42 checks passed"), an optional per-area breakdown, and a
    one-sentence statement of how the score is computed."""

    label: str
    score: int | None
    band: str
    detail: str
    tone: str = "neutral"
    areas: list[ScoreArea] = field(default_factory=list)
    method: str | None = None

    def __post_init__(self):
        if self.tone not in TONES:
            raise ValueError(f"tone must be one of {TONES}, not {self.tone!r}")


def tone_for_score(score: int | None) -> str:
    if score is None:
        return "neutral"
    if score >= 90:
        return "good"
    if score >= 70:
        return "warn"
    return "bad"


@dataclass
class Report:
    title: str
    subtitle: str | None = None
    generated_at: str | None = None
    meta: dict = field(default_factory=dict)
    sections: list[Section] = field(default_factory=list)
    # One to three plain sentences rendered before the first section: what
    # this report is, what it covers, and where to start reading. Markdown
    # by the same contract as section bodies (NOT escaped) -- escape any
    # AWS-sourced string you interpolate with escape_text().
    intro: str | None = None
    kpis: list[Kpi] = field(default_factory=list)
    scorecard: Scorecard | None = None

    def add_section(self, title: str, body_md: str, level: int = 2) -> None:
        self.sections.append(Section(title=title, body_md=body_md, level=level))

    def add_kpi(self, label: str, value, note: str | None = None, tone: str = "neutral") -> None:
        self.kpis.append(Kpi(label=label, value=str(value), note=note, tone=tone))

    def _stamp(self) -> str:
        if not self.generated_at:
            self.generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        return self.generated_at

    # ------------------------------------------------------------ Markdown
    def render_markdown(self) -> str:
        lines = [f"# {escape_text(self.title)}"]
        if self.subtitle:
            lines.append(f"\n_{escape_text(self.subtitle)}_")
        lines.append(f"\nGenerated: {escape_text(self._stamp())}")
        if self.meta:
            lines.append("")
            for key, value in self.meta.items():
                lines.append(f"- **{escape_text(key)}:** {escape_text(value)}")
        if self.scorecard:
            lines.append("\n" + _scorecard_markdown(self.scorecard))
        if self.kpis:
            lines.append("\n" + _kpi_markdown(self.kpis))
        if self.intro:
            lines.append("\n" + self.intro.strip())
        for section in self.sections:
            lines.append("\n" + "#" * section.level + f" {escape_text(section.title)}\n")
            # NOTE: body_md is deliberately NOT escaped -- it is Markdown by
            # contract (tables, chart images, bold). Callers must escape any
            # AWS-sourced string they interpolate into a body themselves;
            # `findings_table()` already does this for every cell.
            lines.append(section.body_md.strip())
        return "\n".join(lines) + "\n"

    # ---------------------------------------------------------------- HTML
    def render_html(self, screen: bool = True) -> str:
        """The standalone HTML report. `screen=False` leaves out the
        browser-only rules (dark mode, phone layout) for the PDF render."""
        stamp = escape_text(self._stamp())
        version = plugin_version()
        generator = f"{PLUGIN_NAME} {version}" if version else PLUGIN_NAME

        meta_items = [("Generated", stamp)] + [(escape_text(k), escape_text(v)) for k, v in self.meta.items()]
        meta_html = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in meta_items)
        subtitle = f'<p class="subtitle">{escape_text(self.subtitle)}</p>' if self.subtitle else ""
        header = (
            '<header class="cover">'
            f'<p class="eyebrow">{escape_text(generator)}</p>'
            f"<h1>{escape_text(self.title)}</h1>"
            f"{subtitle}"
            f'<dl class="meta">{meta_html}</dl>'
            "</header>"
        )

        overview = ""
        if self.scorecard or self.kpis:
            parts = []
            if self.scorecard:
                parts.append(_scorecard_html(self.scorecard))
            if self.kpis:
                parts.append(_kpi_html(self.kpis))
            overview = f'<section class="overview">{"".join(parts)}</section>'

        intro = f'<div class="intro">{_md(self.intro)}</div>' if self.intro else ""

        toc_items: list[str] = []
        body_parts: list[str] = []
        open_sub = False
        for n, section in enumerate(self.sections, start=1):
            anchor = f"sec-{n}"
            title = escape_text(section.title)
            if section.level <= 2:
                if open_sub:
                    toc_items.append("</ol></li>")
                    open_sub = False
                toc_items.append(f'<li><a href="#{anchor}">{title}</a>')
                toc_items.append("</li>")
            else:
                if not toc_items:
                    toc_items.append(f'<li><a href="#{anchor}">{title}</a></li>')
                    continue
                if not open_sub:
                    toc_items.pop()  # reopen the parent <li> for a nested list
                    toc_items.append("<ol>")
                    open_sub = True
                toc_items.append(f'<li><a href="#{anchor}">{title}</a></li>')
            level = min(max(section.level, 2), 6)
            body_parts.append(
                f'<section class="report-section level-{level}" id="{anchor}">'
                f"<h{level}>{title}</h{level}>{_md(section.body_md)}</section>"
            )
        if open_sub:
            toc_items.append("</ol></li>")
        toc = ""
        if len(self.sections) > 2:
            toc = f'<nav class="toc"><p class="toc-title">Contents</p><ol>{"".join(toc_items)}</ol></nav>'

        footer = (
            '<footer class="colophon">'
            f"Generated {stamp} by {escape_text(generator)}. "
            "Every value in this report was read from AWS APIs with read-only calls; "
            "nothing in the account was changed."
            "</footer>"
        )
        body = header + "<main>" + overview + intro + toc + "".join(body_parts) + "</main>" + footer
        css = _CSS + _CSS_SCREEN if screen else _CSS
        return _HTML_TEMPLATE.format(title=escape_text(self.title), css=css, body=_decorate_cells(body))

    # ----------------------------------------------------------------- PDF
    def render_pdf_bytes(self) -> bytes:
        try:
            from weasyprint import HTML
        except ImportError as exc:  # pragma: no cover - exercised only when dep missing
            raise RuntimeError(
                "weasyprint is required for PDF export: pip install -r requirements.txt"
            ) from exc
        except OSError as exc:  # pragma: no cover - exercised only when system libs missing
            # WeasyPrint imports fine from pip but loads Pango at import time.
            raise RuntimeError(
                "PDF export needs the Pango system library (macOS: brew install pango; "
                "Debian/Ubuntu: see README). Markdown/HTML reports are unaffected -- "
                "rerun with --formats md,html to skip PDF."
            ) from exc
        return HTML(string=self.render_html(screen=False)).write_pdf()

    # --------------------------------------------------------------- Save
    def save(self, output_dir: str, basename: str, formats: tuple[str, ...] = ("md", "html", "pdf")) -> dict:
        safe_basename = os.path.basename(basename)
        if not safe_basename or safe_basename in (".", ".."):
            raise ValueError(f"Invalid report basename: {basename!r}")
        basename = safe_basename
        os.makedirs(output_dir, exist_ok=True)
        paths = {}
        if "md" in formats:
            path = os.path.join(output_dir, f"{basename}.md")
            with open(path, "w") as fh:
                fh.write(self.render_markdown())
            paths["md"] = path
        if "html" in formats:
            path = os.path.join(output_dir, f"{basename}.html")
            with open(path, "w") as fh:
                fh.write(self.render_html())
            paths["html"] = path
        if "pdf" in formats:
            path = os.path.join(output_dir, f"{basename}.pdf")
            with open(path, "wb") as fh:
                fh.write(self.render_pdf_bytes())
            paths["pdf"] = path
        return paths


def _md(text: str) -> str:
    return _markdown.markdown(text.strip(), extensions=["tables", "fenced_code", "sane_lists"])


def _score_text(score: int | None) -> str:
    return "n/a" if score is None else f"{score}/100"


def _scorecard_markdown(card: Scorecard) -> str:
    lines = [f"**{escape_text(card.label)}: {_score_text(card.score)} ({escape_text(card.band)})** -- {escape_text(card.detail)}"]
    if card.areas:
        lines.append("")
        lines.append("| Area | Score | Detail |")
        lines.append("| --- | --- | --- |")
        for area in card.areas:
            lines.append(
                f"| {escape_text(area.name)} | {_score_text(area.score)} | {escape_text(area.detail)} |"
            )
    if card.method:
        lines.append(f"\n_{escape_text(card.method)}_")
    return "\n".join(lines)


def _kpi_markdown(kpis: list[Kpi]) -> str:
    lines = ["| Indicator | Value | Note |", "| --- | --- | --- |"]
    for k in kpis:
        lines.append(f"| {escape_text(k.label)} | {escape_text(k.value)} | {escape_text(k.note or '')} |")
    return "\n".join(lines)


_TONE_STROKE = {"good": "#0ca30c", "warn": "#fab219", "bad": "#d03b3b", "neutral": "#c3c2b7"}


def _ring_svg(score: int | None, tone: str) -> str:
    # Colors and type are presentation attributes, not only CSS classes:
    # WeasyPrint's SVG renderer does not apply the page stylesheet to inline
    # SVG. Browsers still let the classes override them (dark mode).
    radius = 52
    circumference = 2 * 3.14159265 * radius
    filled = 0 if score is None else circumference * max(0, min(score, 100)) / 100
    value = "n/a" if score is None else str(score)
    return (
        '<svg class="ring" viewBox="0 0 128 128" width="128" height="128" aria-hidden="true">'
        f'<circle cx="64" cy="64" r="{radius}" class="ring-track" fill="none" stroke="#e1e0d9" stroke-width="11"/>'
        f'<circle cx="64" cy="64" r="{radius}" class="ring-fill tone-{tone}" fill="none" '
        f'stroke="{_TONE_STROKE[tone]}" stroke-width="11" stroke-linecap="round" '
        f'stroke-dasharray="{filled:.1f} {circumference:.1f}" transform="rotate(-90 64 64)"/>'
        f'<text x="64" y="76" text-anchor="middle" class="ring-value" font-size="34" font-weight="700" '
        f'fill="#0b0b0b" font-family="Helvetica Neue, Helvetica, Arial, DejaVu Sans, sans-serif">{value}</text>'
        "</svg>"
    )


def _scorecard_html(card: Scorecard) -> str:
    areas = ""
    if card.areas:
        rows = []
        for area in card.areas:
            pct = 0 if area.score is None else max(0, min(area.score, 100))
            tone = tone_for_score(area.score)
            rows.append(
                "<li>"
                f'<span class="area-name">{escape_text(area.name)}</span>'
                f'<span class="meter"><span class="meter-fill tone-{tone}" style="width:{pct}%"></span></span>'
                f'<span class="area-score">{"n/a" if area.score is None else area.score}</span>'
                f'<span class="area-detail">{escape_text(area.detail)}</span>'
                "</li>"
            )
        areas = f'<ul class="areas">{"".join(rows)}</ul>'
    method = f'<p class="method">{escape_text(card.method)}</p>' if card.method else ""
    return (
        f'<div class="scorecard tone-{card.tone}">'
        '<div class="score-head">'
        f"{_ring_svg(card.score, card.tone)}"
        '<div class="score-text">'
        f'<p class="score-label">{escape_text(card.label)}</p>'
        f'<p class="score-band">{escape_text(card.band)}</p>'
        f'<p class="score-detail">{escape_text(card.detail)}</p>'
        "</div></div>"
        f"{areas}{method}"
        "</div>"
    )


def _kpi_html(kpis: list[Kpi]) -> str:
    tiles = []
    for k in kpis:
        note = f'<p class="kpi-note">{escape_text(k.note)}</p>' if k.note else ""
        tiles.append(
            f'<div class="kpi tone-{k.tone}">'
            f'<p class="kpi-label">{escape_text(k.label)}</p>'
            f'<p class="kpi-value">{escape_text(k.value)}</p>'
            f"{note}</div>"
        )
    return f'<div class="kpis">{"".join(tiles)}</div>'


# Whole-cell values that render as labels in HTML/PDF. Markdown keeps the
# plain word, so the .md file reads cleanly in any viewer.
_CELL_LABELS = {
    "CRITICAL": "sev-critical",
    "HIGH": "sev-high",
    "MEDIUM": "sev-medium",
    "LOW": "sev-low",
    "INFORMATIONAL": "sev-info",
    "PASS": "st-good",
    "FAIL": "st-bad",
    "NO DATA": "st-neutral",
    "enabled": "st-good",
    "recording": "st-good",
    "on": "st-good",
    "NOT enabled": "st-bad",
    "NOT recording": "st-bad",
    "OFF -- gap": "st-bad",
    "unknown": "st-neutral",
}
_CELL_PATTERN = re.compile(
    r"<td>(" + "|".join(re.escape(token) for token in sorted(_CELL_LABELS, key=len, reverse=True)) + r")</td>"
)


# A plain-text cell holding one long unbroken token (an ARN, a URL, a
# bucket name) may break anywhere; ordinary words never split mid-word, so
# narrow columns like "Effort" keep whole words.
_PLAIN_CELL = re.compile(r"<td>([^<]*)</td>")
_LONG_TOKEN = re.compile(r"\S{28,}")


def _decorate_cells(body: str) -> str:
    body = _CELL_PATTERN.sub(
        lambda m: f'<td><span class="label {_CELL_LABELS[m.group(1)]}">{m.group(1)}</span></td>', body
    )
    return _PLAIN_CELL.sub(
        lambda m: f'<td><span class="long">{m.group(1)}</span></td>' if _LONG_TOKEN.search(m.group(1)) else m.group(0),
        body,
    )


def findings_table(rows: list[dict], columns: list[str]) -> str:
    """Render a list of dicts as a Markdown table. Severity and status
    values (HIGH, PASS, NOT enabled, ...) stay plain words in Markdown and
    render as colored labels in HTML/PDF.

    Cell values routinely come straight from live AWS resource data (tags,
    bucket names, IAM usernames, SG descriptions) -- data a limited-privilege
    principal can set to arbitrary text. Every cell is HTML-escaped before
    the table is handed to the Markdown->HTML renderer, so a resource named
    e.g. `<script>...</script>` renders as inert text instead of executing
    when the HTML report is opened in a browser.
    """
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join(["---"] * len(columns)) + " |"
    lines = [header, divider]
    for row in rows:
        cells = []
        for col in columns:
            value = row.get(col, "")
            if isinstance(value, (list, tuple, set)):
                value = ", ".join(str(v) for v in value)
            if col.lower() == "severity" and str(value).upper() in SEVERITY_COLORS:
                value = str(value).upper()
            cells.append(escape_text(value).replace("|", "\\|").replace("\n", "<br>"))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


SEVERITY_MEANINGS = {
    "CRITICAL": "act now; actively exploitable or already failing",
    "HIGH": "fix soon; a real risk, not yet an emergency",
    "MEDIUM": "plan a fix this quarter",
    "LOW": "worth fixing when touching the resource anyway",
    "INFORMATIONAL": "context only, no action required",
    "PASS": "check passed, nothing to do",
}


def severity_legend(levels) -> str:
    """One Markdown line defining each severity level a report actually
    uses -- and only those, so the legend never lists a value the reader
    won't encounter. Pass the set/list of level names present."""
    present = [lvl for lvl in SEVERITY_MEANINGS if lvl in {str(x).upper() for x in levels}]
    if not present:
        return ""
    parts = [f"**{lvl}** = {SEVERITY_MEANINGS[lvl]}" for lvl in present]
    return "Severity levels in this report: " + "; ".join(parts) + "."


def severity_badge(severity: str) -> str:
    """An inline-styled severity label for raw-HTML contexts outside
    tables. Tables don't need it: their severity cells become labels when
    the report renders to HTML."""
    color = SEVERITY_COLORS.get(severity.upper(), "#898781")
    return (
        f'<span style="border:1px solid {color};color:#0b0b0b;padding:1px 8px;'
        f'border-radius:10px;font-size:0.8em;font-weight:600;">{escape_text(severity.upper())}</span>'
    )


def image(data_uri: str, alt: str = "") -> str:
    return f"![{alt}]({data_uri})"


_CSS = """
:root {
  --ink: #0b0b0b; --ink-2: #52514e; --ink-3: #898781;
  --surface: #ffffff; --plane: #f6f6f4; --line: rgba(11,11,11,.10); --line-2: #e1e0d9;
  --accent: #2a78d6; --cover-a: #0f1d33; --cover-b: #1c3a5e;
  --good: #0ca30c; --good-ink: #006300; --good-tint: #e6f5e6;
  --warn: #fab219; --warn-ink: #7a5200; --warn-tint: #fff4d6;
  --bad: #d03b3b; --bad-ink: #9b2222; --bad-tint: #fde8e8;
  --neutral: #c3c2b7; --neutral-ink: #52514e; --neutral-tint: #f0efec;
  --sev-critical: #d03b3b; --sev-high: #ec835a; --sev-medium: #fab219; --sev-low: #2a78d6; --sev-info: #898781;
  --font: "Inter", system-ui, -apple-system, "Segoe UI", "Helvetica Neue", Helvetica, Arial, "DejaVu Sans", sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace;
}
* { box-sizing: border-box; }
html { background: var(--plane); }
body {
  margin: 0 auto; max-width: 1040px; padding: 32px 24px 56px; background: var(--plane);
  color: var(--ink); font-family: var(--font); font-size: 15px; line-height: 1.55;
  }
.cover {
  background: linear-gradient(135deg, var(--cover-a), var(--cover-b)); color: #ffffff;
  border-radius: 16px; padding: 36px 40px 30px; margin-bottom: 24px;
}
.cover .eyebrow { margin: 0 0 10px; font-size: 12px; letter-spacing: .08em; text-transform: uppercase; color: #a9c4ea; font-weight: 600; }
.cover h1 { margin: 0; font-size: 34px; line-height: 1.15; font-weight: 700; letter-spacing: -.01em; border: 0; }
.cover .subtitle { margin: 8px 0 0; font-size: 16px; color: #d6e2f3; }
.cover .meta { display: flex; flex-wrap: wrap; gap: 8px 28px; margin: 24px 0 0; padding-top: 18px; border-top: 1px solid rgba(255,255,255,.18); }
.cover .meta div { min-width: 0; }
.cover .meta dt { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #a9c4ea; }
.cover .meta dd { margin: 2px 0 0; font-size: 14px; color: #ffffff; overflow-wrap: anywhere; }
main { display: block; }
.overview { display: grid; grid-template-columns: minmax(0, 1fr); gap: 16px; margin-bottom: 20px; }
.scorecard, .kpi, .report-section, .toc, .intro {
  background: var(--surface); border: 1px solid var(--line); border-radius: 14px;
}
.scorecard { padding: 22px 24px; }
.score-head { display: flex; align-items: center; gap: 22px; }
.ring { flex: 0 0 auto; }
.score-label { margin: 0; font-size: 12px; text-transform: uppercase; letter-spacing: .07em; color: var(--ink-3); font-weight: 600; }
.score-band { margin: 2px 0 2px; font-size: 26px; font-weight: 700; }
.scorecard.tone-good .score-band { color: var(--good-ink); }
.scorecard.tone-warn .score-band { color: var(--warn-ink); }
.scorecard.tone-bad .score-band { color: var(--bad-ink); }
.score-detail { margin: 0; color: var(--ink-2); }
.areas { list-style: none; margin: 18px 0 0; padding: 16px 0 0; border-top: 1px solid var(--line); display: grid; gap: 9px; }
.areas li { display: grid; grid-template-columns: 170px minmax(80px, 1fr) 42px minmax(0, 1.3fr); align-items: center; gap: 12px; font-size: 13.5px; }
.area-name { font-weight: 600; }
.meter { display: block; height: 8px; border-radius: 4px; background: var(--line-2); overflow: hidden; }
.meter-fill { display: block; height: 100%; border-radius: 4px; }
.meter-fill.tone-good { background: var(--good); } .meter-fill.tone-warn { background: var(--warn); }
.meter-fill.tone-bad { background: var(--bad); } .meter-fill.tone-neutral { background: var(--neutral); }
.area-score { text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }
.area-detail { color: var(--ink-3); font-size: 12.5px; }
.method { margin: 14px 0 0; font-size: 12.5px; color: var(--ink-3); }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.kpi { padding: 14px 16px 13px; border-top: 3px solid var(--neutral); }
.kpi.tone-good { border-top-color: var(--good); } .kpi.tone-warn { border-top-color: var(--warn); }
.kpi.tone-bad { border-top-color: var(--bad); }
.kpi-label { margin: 0; font-size: 12px; color: var(--ink-2); font-weight: 600; }
.kpi-value { margin: 4px 0 0; font-size: 28px; line-height: 1.15; font-weight: 700; }
.kpi-note { margin: 4px 0 0; font-size: 12px; color: var(--ink-3); }
.intro { padding: 18px 24px; margin-bottom: 16px; color: var(--ink-2); }
.intro p { margin: 0; }
.toc { padding: 16px 24px 14px; margin-bottom: 16px; }
.toc-title { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .07em; color: var(--ink-3); font-weight: 600; }
.toc ol { margin: 0; padding-left: 20px; columns: 2; column-gap: 32px; }
.toc ol ol { columns: 1; padding-left: 16px; }
.toc li { margin: 2px 0; break-inside: avoid; }
.toc a { color: var(--ink); text-decoration: none; }
.toc a:hover { color: var(--accent); text-decoration: underline; }
.report-section { padding: 6px 24px 18px; margin-bottom: 16px; }
.report-section.level-3 { margin-top: -8px; border-top-left-radius: 0; border-top-right-radius: 0; }
h2 { font-size: 21px; margin: 18px 0 10px; letter-spacing: -.005em; }
h3 { font-size: 17px; margin: 16px 0 8px; }
h4 { font-size: 15px; margin: 14px 0 6px; }
p { margin: 8px 0; }
ul, ol { margin: 6px 0; padding-left: 22px; }
li { margin: 3px 0; }
em { color: var(--ink-2); }
a { color: var(--accent); }
strong { font-weight: 600; }
blockquote { margin: 12px 0; padding: 10px 16px; border-left: 3px solid var(--accent); background: var(--plane); border-radius: 0 8px 8px 0; color: var(--ink-2); }
table { border-collapse: separate; border-spacing: 0; width: 100%; margin: 12px 0; font-size: 13.5px; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { padding: 8px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); overflow-wrap: break-word; }
.long { overflow-wrap: anywhere; }
th { background: var(--plane); color: var(--ink-2); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
td { font-variant-numeric: tabular-nums; }
.label { display: inline-block; padding: 1px 9px 1px 8px; border-radius: 999px; font-size: 11.5px; font-weight: 600; letter-spacing: .02em; white-space: nowrap; line-height: 1.6; }
.label::before { content: ""; display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; }
.sev-critical { background: var(--bad-tint); color: var(--bad-ink); } .sev-critical::before { background: var(--sev-critical); }
.sev-high { background: #fdeee6; color: #9a3d17; } .sev-high::before { background: var(--sev-high); }
.sev-medium { background: var(--warn-tint); color: var(--warn-ink); } .sev-medium::before { background: var(--sev-medium); }
.sev-low { background: #e8f1fc; color: #1c5cab; } .sev-low::before { background: var(--sev-low); }
.sev-info { background: var(--neutral-tint); color: var(--neutral-ink); } .sev-info::before { background: var(--sev-info); }
.st-good { background: var(--good-tint); color: var(--good-ink); } .st-good::before { background: var(--good); }
.st-bad { background: var(--bad-tint); color: var(--bad-ink); } .st-bad::before { background: var(--bad); }
.st-neutral { background: var(--neutral-tint); color: var(--neutral-ink); } .st-neutral::before { background: var(--neutral); }
img { max-width: 100%; height: auto; display: block; margin: 14px auto; border-radius: 10px; }
code { font-family: var(--mono); font-size: .88em; background: var(--plane); border: 1px solid var(--line); border-radius: 5px; padding: 0 4px; }
pre { font-family: var(--mono); font-size: 12px; background: var(--plane); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; white-space: pre-wrap; overflow-wrap: anywhere; }
pre code { background: none; border: 0; padding: 0; }
.colophon { margin-top: 24px; font-size: 12px; color: var(--ink-3); text-align: center; }
@page {
  size: A4; margin: 16mm 14mm 18mm;
  @bottom-left { content: string(doctitle); font-family: var(--font); font-size: 8pt; color: #898781; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font-family: var(--font); font-size: 8pt; color: #898781; }
}
@page :first { @bottom-left { content: none; } }
@media print {
  html, body { background: #ffffff; }
  body { max-width: none; padding: 0; font-size: 10pt; }
  .cover { border-radius: 10px; padding: 26px 28px 22px; }
  .cover h1 { font-size: 24pt; string-set: doctitle content(); }
  .scorecard, .kpi, .report-section, .toc, .intro { border-radius: 10px; }
  .scorecard, .kpi, .toc, .intro, img, tr, .areas li { break-inside: avoid; }
  .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .kpi-value { font-size: 20pt; }
  .report-section { padding: 2px 18px 12px; }
  h2, h3, h4 { break-after: avoid; }
  table { font-size: 8.5pt; border-radius: 6px; }
  th { font-size: 7.5pt; }
  th, td { padding: 5px 8px; }
  .toc a::after { content: leader(". ") target-counter(attr(href), page); color: #898781; }
  .toc ol { columns: 1; }
  .colophon { font-size: 8pt; }
}
"""


# Rules only a browser understands (dark mode, the phone layout, hover,
# SVG paint from CSS variables). Kept out of the PDF render so WeasyPrint
# doesn't log a warning for each one it can't parse.
_CSS_SCREEN = """
body { -webkit-font-smoothing: antialiased; }
@media screen and (prefers-color-scheme: dark) {
  :root {
    --ink: #f0efec; --ink-2: #c3c2b7; --ink-3: #898781;
    --surface: #1a1a19; --plane: #0f0f0e; --line: rgba(255,255,255,.10); --line-2: #2c2c2a;
    --good-ink: #5fd35f; --good-tint: rgba(12,163,12,.16);
    --warn-ink: #f5c55a; --warn-tint: rgba(250,178,25,.16);
    --bad-ink: #f08a8a; --bad-tint: rgba(208,59,59,.18);
    --neutral-ink: #c3c2b7; --neutral-tint: rgba(255,255,255,.07);
  }
  .figure-card, main img { background: #ffffff; }
}
@media screen and (prefers-color-scheme: dark) {
  .sev-high { background: rgba(236,131,90,.18); color: #f3a585; }
  .sev-low { background: rgba(42,120,214,.2); color: #86b6ef; }
}
.ring-track { stroke: var(--line-2); }
.ring-fill.tone-good { stroke: var(--good); } .ring-fill.tone-warn { stroke: var(--warn); }
.ring-fill.tone-bad { stroke: var(--bad); } .ring-fill.tone-neutral { stroke: var(--neutral); }
.ring-value { fill: var(--ink); }
tbody tr:hover td { background: rgba(42,120,214,.05); }
pre { overflow-x: auto; }
@media (max-width: 720px) {
  body { padding: 16px 16px 40px; font-size: 14.5px; }
  .cover { padding: 26px 22px 22px; }
  .cover h1 { font-size: 27px; }
  .score-head { flex-direction: column; align-items: flex-start; }
  .areas li { grid-template-columns: 1fr 44px; }
  .areas .meter, .areas .area-detail { grid-column: 1 / -1; }
  .toc ol { columns: 1; }
  .report-section { padding: 4px 16px 14px; }
  table { display: block; overflow-x: auto; }
}
"""

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""
