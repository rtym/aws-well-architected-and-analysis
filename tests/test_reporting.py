import pytest

from shared.reporting import charts
from shared.reporting.report import Report, findings_table, severity_badge


def test_bar_chart_returns_svg_data_uri():
    uri = charts.bar_chart(["a", "b", "c"], [1, 2, 3], title="Test")
    assert uri.startswith("data:image/svg+xml;base64,")
    assert len(uri) > 100


def test_pie_chart_all_zero_values_renders_placeholder_instead_of_crashing():
    """Regression test: matplotlib's ax.pie raises ValueError('All wedge
    sizes are zero') on an all-zero input -- a legitimate report scenario
    (e.g. every cost category rounds to $0) must not crash generation."""
    uri = charts.pie_chart(["a", "b"], [0, 0])
    assert uri.startswith("data:image/svg+xml;base64,")


def test_pie_chart_empty_values_renders_placeholder_instead_of_crashing():
    uri = charts.pie_chart([], [])
    assert uri.startswith("data:image/svg+xml;base64,")


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
    assert charts.pie_chart(["a", "b"], [1, 2]).startswith("data:image/svg+xml;base64,")
    assert charts.histogram([1, 2, 2, 3, 3, 3]).startswith("data:image/svg+xml;base64,")
    assert charts.line_chart(["Jan", "Feb"], {"cost": [10, 20]}).startswith("data:image/svg+xml;base64,")
    assert charts.grouped_bar_chart(["Jan", "Feb"], {"a": [1, 2], "b": [3, 4]}).startswith(
        "data:image/svg+xml;base64,"
    )
    assert charts.stacked_bar_chart(["Jan", "Feb"], {"a": [1, 2], "b": [3, 4]}).startswith(
        "data:image/svg+xml;base64,"
    )


def test_findings_table_keeps_severity_a_plain_word_in_markdown():
    """The .md file must read cleanly in any viewer, so a severity stays
    a word there (normalized to upper case); HTML turns it into a label."""
    rows = [
        {"Title": "Open SG", "Severity": "high"},
        {"Title": "Old key", "Severity": "MEDIUM"},
    ]
    table = findings_table(rows, ["Title", "Severity"])
    assert "| Title | Severity |" in table
    assert "| Open SG | HIGH |" in table
    assert "<span" not in table


def test_severity_and_status_cells_render_as_labels_in_html():
    report = Report(title="t")
    report.add_section(
        "s",
        findings_table(
            [{"Severity": "CRITICAL", "Status": "FAIL", "GuardDuty": "NOT enabled", "Note": "HIGH risk"}],
            ["Severity", "Status", "GuardDuty", "Note"],
        ),
    )
    html_out = report.render_html()
    assert '<span class="label sev-critical">CRITICAL</span>' in html_out
    assert '<span class="label st-bad">FAIL</span>' in html_out
    assert '<span class="label st-bad">NOT enabled</span>' in html_out
    # Only a whole-cell match becomes a label, never a word inside text.
    assert "<td>HIGH risk</td>" in html_out


def test_long_tokens_may_break_anywhere_but_words_do_not():
    report = Report(title="t")
    arn = "arn:aws:iam::123456789012:role/service-role/very-long-role-name"
    report.add_section("s", findings_table([{"Resource": arn, "Effort": "Medium"}], ["Resource", "Effort"]))
    html_out = report.render_html()
    assert f'<td><span class="long">{arn}</span></td>' in html_out
    assert "<td>Medium</td>" in html_out


def test_severity_badge_unknown_defaults_gray():
    badge = severity_badge("weird")
    assert "#898781" in badge
    assert "WEIRD" in badge


def test_severity_badge_escapes_its_text():
    assert "<script>" not in severity_badge("<script>")


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


def test_report_intro_renders_between_meta_and_first_section():
    report = Report(
        title="Intro Test",
        meta={"Account": "123456789012"},
        intro="Covers one account. Start with the summary.",
    )
    report.add_section("Summary", "body")
    md = report.render_markdown()
    assert md.index("**Account:**") < md.index("Start with the summary.") < md.index("## Summary")


def test_report_without_intro_renders_unchanged():
    report = Report(title="No Intro")
    report.add_section("Summary", "body")
    assert "None" not in report.render_markdown()


def test_severity_legend_lists_only_the_levels_passed_in_taxonomy_order():
    from shared.reporting.report import severity_legend

    legend = severity_legend(["LOW", "critical"])
    assert legend.index("CRITICAL") < legend.index("LOW")
    for absent in ("HIGH", "MEDIUM", "INFORMATIONAL", "PASS"):
        assert f"**{absent}**" not in legend


def test_severity_legend_empty_or_unknown_levels_returns_empty_string():
    from shared.reporting.report import severity_legend

    assert severity_legend([]) == ""
    assert severity_legend(["BOGUS"]) == ""


def test_line_chart_multi_series_renders_with_legend():
    uri = charts.line_chart(
        ["2024-01", "2024-02"],
        {"Amazon EC2": [10.0, 12.0], "Amazon S3": [5.0, 4.0]},
        title="Trend",
        ylabel="USD",
    )
    assert uri.startswith("data:image/svg+xml;base64,")


def test_pie_chart_all_zero_keeps_its_title():
    uri = charts.pie_chart(["a"], [0], title="Empty but titled")
    assert uri.startswith("data:image/svg+xml;base64,")


def test_histogram_renders_svg_data_uri():
    uri = charts.histogram([1, 2, 2, 3, 5], bins=4, title="H", xlabel="x")
    assert uri.startswith("data:image/svg+xml;base64,")


def test_image_helper_builds_markdown_image():
    from shared.reporting.report import image

    assert image("data:image/png;base64,abc", alt="chart") == "![chart](data:image/png;base64,abc)"


# ------------------------------------------------- scorecard, KPIs, layout
from shared.reporting.report import Kpi, ScoreArea, Scorecard, plugin_version, tone_for_score  # noqa: E402


def _scored_report(**kw) -> Report:
    report = Report(title="Scored", intro="Covers one account.", **kw)
    report.scorecard = Scorecard(
        label="Security posture",
        score=72,
        band="Fair",
        detail="18 of 25 checks passed",
        tone="warn",
        areas=[ScoreArea("Identity", 80, "4 of 5 passed"), ScoreArea("Network", None, "no data")],
        method="Score = passed / evaluated.",
    )
    report.add_kpi("Critical gaps", 2, "3 affected items", "bad")
    report.add_kpi("Regions scanned", 1)
    report.add_section("Summary", "body")
    return report


def test_scorecard_and_kpis_render_as_plain_text_in_markdown():
    md = _scored_report().render_markdown()
    assert "**Security posture: 72/100 (Fair)** -- 18 of 25 checks passed" in md
    assert "| Identity | 80/100 | 4 of 5 passed |" in md
    assert "| Network | n/a | no data |" in md
    assert "_Score = passed / evaluated._" in md
    assert "| Critical gaps | 2 | 3 affected items |" in md
    assert "| Regions scanned | 1 |  |" in md
    # Headline numbers come before the orientation paragraph and sections.
    assert md.index("Security posture") < md.index("Critical gaps") < md.index("Covers one account.") < md.index("## Summary")


def test_scorecard_and_kpis_render_as_ring_meters_and_tiles_in_html():
    html_out = _scored_report().render_html()
    assert 'class="ring"' in html_out and ">72</text>" in html_out
    assert 'stroke="#fab219"' in html_out  # warn tone painted without CSS
    assert 'class="meter-fill tone-warn" style="width:80%"' in html_out
    assert 'class="meter-fill tone-neutral" style="width:0%"' in html_out
    assert '<div class="kpi tone-bad"><p class="kpi-label">Critical gaps</p><p class="kpi-value">2</p>' in html_out


def test_scorecard_without_a_score_says_so():
    report = Report(title="t")
    report.scorecard = Scorecard("Posture", None, "Not evaluated", "no checks had data")
    assert "**Posture: n/a (Not evaluated)**" in report.render_markdown()
    assert ">n/a</text>" in report.render_html()


@pytest.mark.parametrize("field", ["kpi_label", "kpi_value", "kpi_note", "score_label", "score_band", "score_detail", "area", "method"])
def test_scorecard_and_kpi_text_is_escaped(field):
    payload = "<script>alert(1)</script>"
    report = Report(title="t")
    kpi = {"label": "l", "value": "v", "note": "n"}
    card = {"label": "l", "band": "b", "detail": "d", "method": "m", "area": "a"}
    if field.startswith("kpi_"):
        kpi[field[4:]] = payload
    elif field.startswith("score_"):
        card[field[6:]] = payload
    else:
        card[field] = payload
    report.add_kpi(kpi["label"], kpi["value"], kpi["note"])
    report.scorecard = Scorecard(card["label"], 50, card["band"], card["detail"], areas=[ScoreArea(card["area"], 50)], method=card["method"])
    report.add_section("s", "b")
    for rendered in (report.render_markdown(), report.render_html()):
        assert payload not in rendered


def test_tone_is_validated():
    with pytest.raises(ValueError, match="tone"):
        Kpi("l", "v", tone="red")
    with pytest.raises(ValueError, match="tone"):
        Scorecard("l", 1, "b", "d", tone="green")


@pytest.mark.parametrize("score, tone", [(None, "neutral"), (95, "good"), (90, "good"), (89, "warn"), (70, "warn"), (69, "bad")])
def test_tone_for_score(score, tone):
    assert tone_for_score(score) == tone


def test_html_has_a_cover_with_meta_and_generator_version():
    report = Report(title="Cover", subtitle="Sub", meta={"Account": "123456789012"}, generated_at="2026-11-07T10:00:00+00:00")
    report.add_section("s", "b")
    html_out = report.render_html()
    assert '<header class="cover">' in html_out
    assert f"aws-well-architected-and-analysis {plugin_version()}" in html_out
    assert "<dt>Account</dt><dd>123456789012</dd>" in html_out
    assert "<dt>Generated</dt><dd>2026-11-07T10:00:00+00:00</dd>" in html_out
    assert '<p class="subtitle">Sub</p>' in html_out


def test_plugin_version_matches_the_manifest():
    import json
    from pathlib import Path

    manifest = Path(__file__).resolve().parents[1] / ".claude-plugin" / "plugin.json"
    assert plugin_version() == json.loads(manifest.read_text())["version"]


def test_toc_lists_sections_and_nests_subsections():
    report = Report(title="t")
    report.add_section("Lead sub", "x", level=3)  # a subsection before any section
    report.add_section("One", "x")
    report.add_section("One A", "x", level=3)
    report.add_section("One B", "x", level=3)
    report.add_section("Two", "x")
    html_out = report.render_html()
    toc = html_out.split('<nav class="toc">', 1)[1].split("</nav>", 1)[0]
    assert toc.count("<li>") == 5
    assert '<li><a href="#sec-2">One</a><ol><li><a href="#sec-3">One A</a></li><li><a href="#sec-4">One B</a></li></ol></li>' in toc
    assert '<section class="report-section level-3" id="sec-3"><h3>One A</h3>' in html_out


def test_toc_closes_a_nested_list_at_the_end():
    report = Report(title="t")
    report.add_section("One", "x")
    report.add_section("Two", "x")
    report.add_section("Two A", "x", level=3)
    toc = report.render_html().split('<nav class="toc">', 1)[1].split("</nav>", 1)[0]
    assert toc.endswith("</ol></li></ol>")


def test_short_reports_skip_the_toc():
    report = Report(title="t")
    report.add_section("Only", "x")
    report.add_section("Two", "x")
    assert '<nav class="toc">' not in report.render_html()


def test_pdf_html_leaves_out_browser_only_css():
    report = _scored_report()
    screen = report.render_html()
    pdf_html = report.render_html(screen=False)
    assert "prefers-color-scheme" in screen and "prefers-color-scheme" not in pdf_html
    assert "max-width: 720px" not in pdf_html
    assert "target-counter" in pdf_html  # TOC page numbers stay


def test_pdf_render_logs_no_weasyprint_warnings(caplog):
    """WeasyPrint logs a warning for each CSS rule it can't parse; with no
    logging configured those land in the user's terminal on every run."""
    import logging

    report = _scored_report()
    report.add_section("Chart", f"![c]({charts.severity_chart({'HIGH': 2, 'LOW': 1})})", level=3)
    with caplog.at_level(logging.WARNING, logger="weasyprint"):
        assert report.render_pdf_bytes()[:4] == b"%PDF"
    assert [r.getMessage() for r in caplog.records if r.name.startswith("weasyprint")] == []


# ------------------------------------------------------------------ charts
def _svg(uri: str) -> str:
    import base64

    assert uri.startswith("data:image/svg+xml;base64,")
    return base64.b64decode(uri.split(",", 1)[1]).decode()


def test_single_series_bars_share_one_color():
    svg = _svg(charts.bar_chart(["a", "b", "c"], [3, 1, 2]))
    assert svg.count(charts.PALETTE[0]) >= 3
    assert charts.PALETTE[1] not in svg


def test_severity_chart_uses_severity_colors_in_severity_order():
    svg = _svg(charts.severity_chart({"LOW": 1, "CRITICAL": 2, "MEDIUM": 0}))
    assert charts.SEVERITY_FILL["CRITICAL"] in svg and charts.SEVERITY_FILL["LOW"] in svg
    assert charts.SEVERITY_FILL["MEDIUM"] not in svg  # zero levels are left out


def test_severity_chart_with_nothing_renders_no_data():
    assert charts.severity_chart({"HIGH": 0}).startswith("data:image/svg+xml;base64,")


def test_bar_chart_validates_colors_and_handles_no_bars():
    with pytest.raises(ValueError, match="one entry per bar"):
        charts.bar_chart(["a", "b"], [1, 2], colors=["#000000"])
    assert charts.bar_chart([], []).startswith("data:image/svg+xml;base64,")


def test_bar_chart_rotates_long_vertical_labels():
    assert charts.bar_chart(["a long category label", "b"], [1.5, 2.5], value_format="number")


def test_charts_render_identical_svg_for_identical_data():
    """Stable output keeps regenerated reports diffable."""
    assert charts.bar_chart(["a", "b"], [1, 2]) == charts.bar_chart(["a", "b"], [1, 2])


def test_more_series_than_colors_is_an_error_not_a_reused_color():
    series = {f"s{i}": [1] for i in range(9)}
    with pytest.raises(ValueError, match="Other"):
        charts.line_chart(["Jan"], series)


def test_donut_folds_the_tail_into_other():
    labels = [f"svc{i}" for i in range(9)]
    svg = _svg(charts.donut_chart(labels, [9, 8, 7, 6, 5, 4, 3, 2, 1]))
    assert charts.OTHER_COLOR in svg
    assert charts.PALETTE[5] not in svg  # six segments: five services + Other


def test_donut_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        charts.donut_chart(["a", "b"], [1])


def test_line_chart_labels_the_latest_value_of_a_single_series():
    assert charts.line_chart([f"m{i}" for i in range(8)], {"cost": [1000.0 * i for i in range(8)]}, value_format="usd")


def test_stacked_bar_chart_takes_meaningful_colors():
    svg = _svg(
        charts.stacked_bar_chart(
            ["2026-01", "2026-02", "2026-03", "2026-04", "2026-05"],
            {"EC2": [1, 2, 3, 4, 5], "Other": [1, 1, 1, 1, 1]},
            colors={"EC2": charts.PALETTE[0], "Other": charts.OTHER_COLOR},
            value_format="usd",
        )
    )
    assert charts.OTHER_COLOR in svg


def test_grouped_bar_chart_rotates_many_categories():
    assert charts.grouped_bar_chart([f"c{i}" for i in range(6)], {"a": [1] * 6, "b": [2] * 6})


@pytest.mark.parametrize(
    "value, fmt, expected",
    [
        (0, "count", "0"),
        (1284, "count", "1.3K"),
        (12900, "count", "12.9K"),
        (250000, "count", "250K"),
        (4_200_000, "usd", "$4.2M"),
        (-1500, "usd", "-$1.5K"),
        (12.5, "number", "12.5"),
        (512, "bytes", "512 B"),
        (3 * 1024**3, "bytes", "3.0 GiB"),
        (87.4, "percent", "87%"),
        (2e12, "count", "2T"),
        (-2000, "count", "-2K"),
    ],
)
def test_format_value(value, fmt, expected):
    assert charts.format_value(value, fmt) == expected


def test_font_families_always_end_with_the_bundled_fallback():
    families = charts._font_families()
    assert families[-1] == "DejaVu Sans"


def test_horizontal_bar_chart_puts_the_axis_label_on_the_value_axis():
    assert charts.bar_chart(["a", "b"], [1, 2], ylabel="Count", horizontal=True)
