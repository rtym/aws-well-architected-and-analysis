#!/usr/bin/env python3
"""Render a Markdown test dashboard from pytest's junit.xml and coverage.xml.

CI appends the output to $GITHUB_STEP_SUMMARY, so every workflow run shows
a dashboard on its summary page: pass/fail/skip counts, total line
coverage, the least-covered files, and the full detail of any failure --
without downloading artifacts or reading the log.

Usage:
    python .github/scripts/test_summary.py junit.xml coverage.xml [label]

Deterministic and dependency-free (stdlib XML only); unit-tested in
tests/test_ci_summary.py.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

WORST_FILES_SHOWN = 5


def junit_summary(junit_path: Path) -> dict:
    root = ET.parse(junit_path).getroot()
    # pytest writes <testsuites><testsuite .../></testsuites>; tolerate a
    # bare <testsuite> root too.
    suites = root.findall("testsuite") if root.tag == "testsuites" else [root]
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0}
    failures: list[dict] = []
    for suite in suites:
        for key in ("tests", "failures", "errors", "skipped"):
            totals[key] += int(suite.get(key, 0))
        totals["time"] += float(suite.get("time", 0))
        for case in suite.iter("testcase"):
            for kind in ("failure", "error"):
                node = case.find(kind)
                if node is not None:
                    failures.append(
                        {
                            "test": f"{case.get('classname', '?')}::{case.get('name', '?')}",
                            "message": (node.get("message") or "").strip(),
                            "detail": (node.text or "").strip(),
                        }
                    )
    totals["passed"] = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
    return {"totals": totals, "failures": failures}


def coverage_summary(coverage_path: Path) -> dict:
    root = ET.parse(coverage_path).getroot()
    total_rate = float(root.get("line-rate", 0))
    files = []
    for cls in root.iter("class"):
        files.append({"file": cls.get("filename", "?"), "rate": float(cls.get("line-rate", 0))})
    files.sort(key=lambda f: (f["rate"], f["file"]))
    return {"total_rate": total_rate, "worst": files[:WORST_FILES_SHOWN]}


def render(junit: dict, coverage: dict | None, label: str = "") -> str:
    totals = junit["totals"]
    ok = not junit["failures"]
    title = "Test results" + (f" ({label})" if label else "")
    lines = [f"## {'✅' if ok else '❌'} {title}", ""]
    lines += [
        "| Passed | Failed | Errors | Skipped | Duration |",
        "| --- | --- | --- | --- | --- |",
        f"| {totals['passed']} | {totals['failures']} | {totals['errors']} "
        f"| {totals['skipped']} | {totals['time']:.1f}s |",
        "",
    ]

    if coverage is not None:
        lines.append(f"**Line coverage: {coverage['total_rate']:.1%}** -- least-covered files:")
        lines += ["", "| File | Coverage |", "| --- | --- |"]
        lines += [f"| `{f['file']}` | {f['rate']:.1%} |" for f in coverage["worst"]]
        lines.append("")

    for failure in junit["failures"]:
        lines.append(f"<details><summary>❌ <code>{failure['test']}</code></summary>")
        lines += ["", "```", failure["message"], "", failure["detail"], "```", "</details>", ""]

    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    junit_path = Path(argv[1])
    coverage_path = Path(argv[2]) if len(argv) > 2 and Path(argv[2]).exists() else None
    label = argv[3] if len(argv) > 3 else ""

    junit = junit_summary(junit_path)
    coverage = coverage_summary(coverage_path) if coverage_path else None
    print(render(junit, coverage, label))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
