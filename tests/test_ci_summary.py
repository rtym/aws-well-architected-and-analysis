"""Tests for the CI dashboard generator (.github/scripts/test_summary.py).

The script is CI glue, but it is the only thing standing between a red run
and a readable explanation on the run's summary page -- a parsing bug
would surface exactly when a maintainer is debugging a failure, the worst
possible moment. Pin its behaviour against synthetic junit/coverage XML.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location("test_summary", ROOT / ".github" / "scripts" / "test_summary.py")
test_summary = importlib.util.module_from_spec(spec)
sys.modules["test_summary"] = test_summary
spec.loader.exec_module(test_summary)


JUNIT_GREEN = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="0" failures="0" skipped="2" tests="431" time="14.9">
    <testcase classname="tests.test_reporting" name="test_ok" time="0.01"/>
  </testsuite>
</testsuites>
"""

JUNIT_RED = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="1" failures="1" skipped="0" tests="10" time="2.0">
    <testcase classname="tests.test_x" name="test_boom" time="0.1">
      <failure message="assert 1 == 2">full traceback here</failure>
    </testcase>
    <testcase classname="tests.test_y" name="test_crash" time="0.1">
      <error message="RuntimeError: nope">error traceback</error>
    </testcase>
  </testsuite>
</testsuites>
"""

COVERAGE_XML = """<?xml version="1.0" ?>
<coverage line-rate="0.981">
  <packages>
    <package name="shared">
      <classes>
        <class filename="shared/reporting/report.py" line-rate="0.99"/>
        <class filename="shared/awslib/collectors/cost.py" line-rate="0.92"/>
        <class filename="shared/awslib/collectors/vpc.py" line-rate="1.0"/>
      </classes>
    </package>
  </packages>
</coverage>
"""


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return path


def test_green_run_renders_counts_and_coverage(tmp_path):
    junit = test_summary.junit_summary(_write(tmp_path, "junit.xml", JUNIT_GREEN))
    coverage = test_summary.coverage_summary(_write(tmp_path, "coverage.xml", COVERAGE_XML))

    out = test_summary.render(junit, coverage, label="Python 3.13")

    assert out.startswith("## ✅ Test results (Python 3.13)")
    assert "| 429 | 0 | 0 | 2 | 14.9s |" in out  # passed = tests - skipped
    assert "**Line coverage: 98.1%**" in out
    # Least-covered files first.
    assert out.index("collectors/cost.py") < out.index("reporting/report.py")
    assert "❌" not in out


def test_red_run_lists_every_failure_with_detail(tmp_path):
    junit = test_summary.junit_summary(_write(tmp_path, "junit.xml", JUNIT_RED))

    out = test_summary.render(junit, coverage=None)

    assert out.startswith("## ❌ Test results")
    assert "| 8 | 1 | 1 | 0 |" in out
    assert "tests.test_x::test_boom" in out
    assert "assert 1 == 2" in out
    assert "full traceback here" in out
    assert "tests.test_y::test_crash" in out
    assert "RuntimeError: nope" in out


def test_cli_accepts_missing_coverage_file(tmp_path, capsys):
    """Coverage can be absent (e.g. pytest crashed before writing it); the
    dashboard must still render the test counts rather than erroring."""
    junit_path = _write(tmp_path, "junit.xml", JUNIT_GREEN)

    rc = test_summary.main(["prog", str(junit_path), str(tmp_path / "missing-coverage.xml")])

    assert rc == 0
    out = capsys.readouterr().out
    assert "Test results" in out
    assert "Line coverage" not in out


def test_cli_without_args_exits_nonzero(capsys):
    assert test_summary.main(["prog"]) == 2
