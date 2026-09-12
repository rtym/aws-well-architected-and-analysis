import pytest

from shared.reporting import charts
from shared.reporting.report import Report, findings_table, severity_badge


def test_bar_chart_returns_png_data_uri():
    uri = charts.bar_chart(["a", "b", "c"], [1, 2, 3], title="Test")
    assert uri.startswith("data:image/png;base64,")
    assert len(uri) > 100


def test_pie_chart_all_zero_values_renders_placeholder_instead_of_crashing():
    """Regression test: matplotlib's ax.pie raises ValueError('All wedge
    sizes are zero') on an all-zero input -- a legitimate report scenario
    (e.g. every cost category rounds to $0) must not crash generation."""
    uri = charts.pie_chart(["a", "b"], [0, 0])
    assert uri.startswith("data:image/png;base64,")


def test_pie_chart_empty_values_renders_placeholder_instead_of_crashing():
    uri = charts.pie_chart([], [])
    assert uri.startswith("data:image/png;base64,")


def test_grouped_bar_chart_raises_clear_error_on_length_mismatch():
    with pytest.raises(ValueError, match="length"):
        charts.grouped_bar_chart(["a", "b", "c"], {"x": [1, 2]})


def test_stacked_bar_chart_raises_clear_error_on_length_mismatch():
    with pytest.raises(ValueError, match="length"):
        charts.stacked_bar_chart(["a", "b"], {"x": [1, 2, 3]})


def test_line_chart_raises_clear_error_on_length_mismatch():
    with pytest.raises(ValueError, match="length"):
        charts.line_chart(["Jan", "Feb"], {"cost": [10]})


def test_all_chart_types_render():
    assert charts.pie_chart(["a", "b"], [1, 2]).startswith("data:image/png;base64,")
    assert charts.histogram([1, 2, 2, 3, 3, 3]).startswith("data:image/png;base64,")
    assert charts.line_chart(["Jan", "Feb"], {"cost": [10, 20]}).startswith("data:image/png;base64,")
    assert charts.grouped_bar_chart(["Jan", "Feb"], {"a": [1, 2], "b": [3, 4]}).startswith(
        "data:image/png;base64,"
    )
    assert charts.stacked_bar_chart(["Jan", "Feb"], {"a": [1, 2], "b": [3, 4]}).startswith(
        "data:image/png;base64,"
    )


def test_findings_table_renders_markdown_with_severity_badge():
    rows = [
        {"Title": "Open SG", "Severity": "HIGH"},
        {"Title": "Old key", "Severity": "MEDIUM"},
    ]
    table = findings_table(rows, ["Title", "Severity"])
    assert "| Title | Severity |" in table
    assert "Open SG" in table
    assert "background:#dc2626" in table  # HIGH badge color


def test_severity_badge_unknown_defaults_gray():
    badge = severity_badge("weird")
    assert "#6b7280" in badge


def test_findings_table_escapes_html_in_cell_values():
    """Regression test: cell values come straight from live AWS resource
    data (tags, bucket names, IAM usernames) which a limited-privilege
    principal can set to arbitrary text. A resource named with an HTML/
    script payload must render as inert text in the HTML report, not
    execute -- this is a real stored-XSS path if unescaped."""
    rows = [{"Bucket": "<script>alert(1)</script>", "Issue": "public"}]
    table = findings_table(rows, ["Bucket", "Issue"])

    assert "<script>alert(1)</script>" not in table
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in table

    report = Report(title="XSS check")
    report.add_section("Findings", table)
    html_out = report.render_html()
    assert "<script>alert(1)</script>" not in html_out


@pytest.mark.parametrize(
    "field",
    ["title", "subtitle", "meta_key", "meta_value", "section_title"],
)
def test_report_escapes_every_plain_text_field(field):
    """Regression test: `findings_table` was hardened first, but Report's
    own plain-text fields (title/subtitle/meta/section headings) were still
    unescaped sinks -- and title additionally lands inside <title>. All of
    these can carry AWS-sourced strings (e.g. a workload or bucket name),
    so each must render inert in the browser-opened HTML report."""
    payload = "<script>alert(1)</script>"
    kwargs = {"title": "Safe title"}
    section_title = "Safe section"

    if field == "title":
        kwargs["title"] = f"T {payload}"
    elif field == "subtitle":
        kwargs["subtitle"] = f"S {payload}"
    elif field == "meta_key":
        kwargs["meta"] = {f"K {payload}": "v"}
    elif field == "meta_value":
        kwargs["meta"] = {"k": f"V {payload}"}
    elif field == "section_title":
        section_title = f"Sec {payload}"

    report = Report(**kwargs)
    report.add_section(section_title, "body")

    for rendered in (report.render_markdown(), report.render_html()):
        assert payload not in rendered
    assert "&lt;script&gt;" in report.render_html()


def test_report_title_escaped_inside_html_title_element():
    report = Report(title="<script>alert(1)</script>")
    report.add_section("s", "b")
    html_out = report.render_html()
    title_line = next(line for line in html_out.splitlines() if "<title>" in line)
    assert "<script>" not in title_line
    assert "&lt;script&gt;" in title_line


def test_report_section_body_is_not_escaped_by_contract():
    """Section bodies ARE Markdown by contract -- tables, bold, and chart
    images must survive. Callers escape AWS data going into a body
    themselves (findings_table does it automatically). Guard that contract
    so a future 'escape everything' change doesn't silently break every
    report's tables and charts."""
    report = Report(title="t")
    report.add_section("s", "**bold** and a [link](http://example.com)\n\n| a | b |\n| --- | --- |\n| 1 | 2 |")
    html_out = report.render_html()
    assert "<strong>bold</strong>" in html_out
    assert "<table>" in html_out


def test_findings_table_escapes_ampersand_and_quotes():
    rows = [{"Name": 'Tom & "Jerry" <b>'}]
    table = findings_table(rows, ["Name"])
    assert "Tom &amp; \"Jerry\" &lt;b&gt;" in table


def test_findings_table_joins_list_values_instead_of_python_repr():
    """A cell value that's a list (e.g. FindingReasonCodes) should render as
    a clean comma-joined string, not Python's str(list) repr."""
    rows = [{"Finding": "x", "Reasons": ["Overprovisioned", "Idle"]}]
    table = findings_table(rows, ["Finding", "Reasons"])
    assert "Overprovisioned, Idle" in table
    assert "[" not in table and "'" not in table


def test_findings_table_pipe_and_newline_still_handled_alongside_escaping():
    rows = [{"Name": "a|b", "Note": "line1\nline2"}]
    table = findings_table(rows, ["Name", "Note"])
    assert "a\\|b" in table
    assert "line1<br>line2" in table


def test_report_render_markdown_includes_sections_and_meta():
    report = Report(title="Cost Report", subtitle="Account 123", meta={"Account": "123456789012"})
    report.add_section("Summary", "Total spend was $100.")
    md = report.render_markdown()
    assert "# Cost Report" in md
    assert "Account 123" in md
    assert "**Account:** 123456789012" in md
    assert "## Summary" in md
    assert "Total spend was $100." in md


def test_report_render_html_wraps_markdown():
    report = Report(title="Security Report")
    report.add_section("Findings", findings_table([{"Title": "X", "Severity": "LOW"}], ["Title", "Severity"]))
    html = report.render_html()
    assert "<html" in html
    assert "Security Report" in html
    assert "<table>" in html


def test_report_render_pdf_bytes_is_a_valid_pdf():
    report = Report(title="PDF Smoke Test")
    report.add_section("Chart", f"![chart]({charts.bar_chart(['a'], [1])})")
    pdf_bytes = report.render_pdf_bytes()
    assert pdf_bytes[:4] == b"%PDF"


def test_report_save_writes_all_formats(tmp_path):
    report = Report(title="Save Test")
    report.add_section("Body", "hello")
    paths = report.save(str(tmp_path), "save-test")
    assert set(paths) == {"md", "html", "pdf"}
    for path in paths.values():
        assert __import__("os").path.getsize(path) > 0


def test_report_save_sanitizes_path_traversal_in_basename(tmp_path):
    """Regression test: basename is currently always a hardcoded literal at
    every call site, but save() itself had no defense if that ever changed
    -- a basename containing '/' or '..' must not escape output_dir. It's
    sanitized down to just the final path component rather than rejected
    outright (matching os.path.basename's own semantics)."""
    import os

    report = Report(title="Traversal Test")
    report.add_section("Body", "hello")

    paths = report.save(str(tmp_path), "../evil", formats=("md",))
    assert os.path.dirname(paths["md"]) == str(tmp_path)
    assert os.path.basename(paths["md"]) == "evil.md"

    paths2 = report.save(str(tmp_path), "sub/dir/report", formats=("md",))
    assert os.path.dirname(paths2["md"]) == str(tmp_path)
    assert os.path.basename(paths2["md"]) == "report.md"


def test_report_save_rejects_basename_that_sanitizes_to_nothing(tmp_path):
    report = Report(title="Empty Basename Test")
    report.add_section("Body", "hello")

    for bad in ("", ".", "..", "/"):
        with pytest.raises(ValueError):
            report.save(str(tmp_path), bad, formats=("md",))
