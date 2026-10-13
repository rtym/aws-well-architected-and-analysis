"""Assemble a Report from Markdown sections (which may embed chart images as
base64 data URIs from `shared.reporting.charts`) and render it to Markdown,
a styled standalone HTML file, and a PDF (via WeasyPrint, HTML -> PDF).
"""
from __future__ import annotations

import datetime
import html
import os
from dataclasses import dataclass, field

import markdown as _markdown

SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFORMATIONAL": "#6b7280",
    "PASS": "#16a34a",
}


def escape_text(value) -> str:
    """HTML-escape a plain-text report field (title, subtitle, meta value,
    section heading, or table cell).

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
class Report:
    title: str
    subtitle: str | None = None
    generated_at: str | None = None
    meta: dict = field(default_factory=dict)
    sections: list[Section] = field(default_factory=list)

    def add_section(self, title: str, body_md: str, level: int = 2) -> None:
        self.sections.append(Section(title=title, body_md=body_md, level=level))

    # ------------------------------------------------------------ Markdown
    def render_markdown(self) -> str:
        lines = [f"# {escape_text(self.title)}"]
        if self.subtitle:
            lines.append(f"\n_{escape_text(self.subtitle)}_")
        stamp = self.generated_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        lines.append(f"\nGenerated: {escape_text(stamp)}")
        if self.meta:
            lines.append("")
            for key, value in self.meta.items():
                lines.append(f"- **{escape_text(key)}:** {escape_text(value)}")
        for section in self.sections:
            lines.append("\n" + "#" * section.level + f" {escape_text(section.title)}\n")
            # NOTE: body_md is deliberately NOT escaped -- it is Markdown by
            # contract (tables, chart images, bold). Callers must escape any
            # AWS-sourced string they interpolate into a body themselves;
            # `findings_table()` already does this for every cell.
            lines.append(section.body_md.strip())
        return "\n".join(lines) + "\n"

    # ---------------------------------------------------------------- HTML
    def render_html(self) -> str:
        md_body = self.render_markdown()
        body_html = _markdown.markdown(
            md_body, extensions=["tables", "fenced_code", "toc", "sane_lists"]
        )
        # self.title is escaped here (not re-escaped -- render_markdown
        # escapes its own copy from the same raw source) because it lands
        # inside <title> element content.
        return _HTML_TEMPLATE.format(title=escape_text(self.title), body=body_html)

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
        return HTML(string=self.render_html()).write_pdf()

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


def findings_table(rows: list[dict], columns: list[str]) -> str:
    """Render a list of dicts as a Markdown table, with a `Severity` column
    (if present) rendered as a colored badge in HTML/PDF output.

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
                cell = severity_badge(str(value))
            else:
                cell = escape_text(value).replace("|", "\\|").replace("\n", "<br>")
            cells.append(cell)
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "#6b7280")
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;'
        f'border-radius:10px;font-size:0.8em;font-weight:600;">{severity.upper()}</span>'
    )


def image(data_uri: str, alt: str = "") -> str:
    return f"![{alt}]({data_uri})"


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  :root {{
    --bg: #ffffff; --text: #1f2937; --muted: #6b7280; --border: #e5e7eb; --accent: #2563eb;
  }}
  body {{
    background: var(--bg); color: var(--text); margin: 0 auto; max-width: 960px;
    padding: 2.5rem 2rem 4rem; font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.55;
  }}
  h1 {{ font-size: 1.9rem; border-bottom: 3px solid var(--accent); padding-bottom: .4rem; }}
  h2 {{ font-size: 1.4rem; margin-top: 2.2rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }}
  h3 {{ font-size: 1.15rem; margin-top: 1.6rem; color: #111827; }}
  em {{ color: var(--muted); }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.92rem; }}
  th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f3f4f6; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  img {{ max-width: 100%; height: auto; display: block; margin: 1rem auto; }}
  code, pre {{ background: #f3f4f6; border-radius: 4px; }}
  pre {{ padding: 10px; overflow-x: auto; }}
  ul {{ margin: 0.3rem 0; }}
  @media print {{
    body {{ max-width: none; }}
    h2 {{ page-break-before: auto; }}
  }}
</style>
</head>
<body>
{body}
</body>
</html>
"""
