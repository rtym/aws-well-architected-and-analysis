"""Prose quality of everything a stakeholder reads.

Two surfaces, one lint (shared/reporting/prose_lint.py):

1. The *generated artifacts* -- every skill script's rendered Markdown
   report must open with an orientation paragraph, carry no machine-voice
   filler, no unfilled template placeholders, and no copy-paste duplicated
   lines or headings.
2. The *plugin's own documentation* (SKILL.md files, references, README,
   CONTRIBUTING, ...) -- same filler/placeholder vocabulary rules, since
   these are what Claude imitates when writing report prose. The style
   reference itself and the diagram conventions deliberately name the
   banned words, so they are exempt.

Each lint rule also has a negative test proving it fires -- a lint that
cannot fail guards nothing.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from shared.reporting.prose_lint import lint_markdown

ROOT = Path(__file__).resolve().parents[1]

# These two deliberately name the banned vocabulary in order to ban it.
FILLER_EXEMPT_DOCS = {
    "skills/aws-architecture-gap-analysis/references/writing-style.md",
    "skills/aws-architecture-discovery/references/diagram-conventions.md",
}

WRITING_STYLE_DOC = "skills/aws-architecture-gap-analysis/references/writing-style.md"


def _load(module_name: str, script_path: str):
    path = ROOT / script_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------- lint rules
def test_lint_passes_a_clean_report():
    clean = (
        "# Title\n\nThis report covers one account. Start with the summary.\n\n"
        "## Summary\n\nTwo items found: 3 idle volumes and 1 open port.\n"
    )
    assert lint_markdown(clean) == []


def test_lint_flags_banned_filler():
    findings = lint_markdown("# T\n\nWe leverage a robust, comprehensive approach.\n## S\nx\n")
    rules = {f.rule for f in findings}
    assert "banned-phrase" in rules
    named = {f.detail.split("'")[1] for f in findings if f.rule == "banned-phrase"}
    assert named == {"leverage", "robust", "comprehensive"}


def test_lint_flags_unfilled_placeholders():
    text = "# T\n\nAccount <AccountId> reviewed on YYYY-MM-DD. TODO: fill in.\n## S\nx\n"
    findings = [f for f in lint_markdown(text) if f.rule == "unfilled-placeholder"]
    assert len(findings) == 3


def test_lint_flags_duplicated_consecutive_line():
    text = "# T\n\nIntro here.\n\n## S\n\nGenerated for account 1.\nGenerated for account 1.\n"
    findings = [f for f in lint_markdown(text) if f.rule == "duplicated-line"]
    assert len(findings) == 1


def test_lint_flags_duplicate_heading():
    text = "# T\n\nIntro here.\n\n## Findings\n\na\n\n## Findings\n\nb\n"
    findings = [f for f in lint_markdown(text) if f.rule == "duplicate-heading"]
    assert len(findings) == 1


def test_lint_flags_missing_orientation():
    text = "# T\n\n## Straight Into It\n\ncontent\n"
    findings = [f for f in lint_markdown(text) if f.rule == "missing-orientation"]
    assert len(findings) == 1
    assert lint_markdown(text, require_intro=False) == []


def test_lint_exempts_code_fences_code_spans_and_table_rows():
    text = (
        "# T\n\nIntro: run `--mode seamless` against <profile> placeholders in code only.\n\n"
        "## S\n\n```bash\nleverage --robust <AccountId>  # commands are exempt\n```\n\n"
        "| Finding |\n| --- |\n| How do you utilize observability? |\n"
    )
    # The backtick span shields "seamless"; "<profile>" outside a span is a
    # genuine leak and must still fire -- so strip it from this fixture.
    text = text.replace(" against <profile> placeholders", "")
    assert lint_markdown(text) == []


def test_lint_metadata_lines_do_not_count_as_orientation():
    text = "# T\n\n_subtitle_\n\nGenerated: now\n\n- **Account:** 1\n\n## S\n\nx\n"
    assert any(f.rule == "missing-orientation" for f in lint_markdown(text))


# ------------------------------------------------- plugin's own documentation
REPO_DOCS = sorted(
    p.relative_to(ROOT).as_posix()
    for p in list(ROOT.glob("*.md")) + list((ROOT / "skills").rglob("*.md"))
)


@pytest.mark.parametrize("rel_path", REPO_DOCS)
def test_plugin_documentation_is_free_of_filler_and_placeholders(rel_path):
    """The plugin's own prose is what the model imitates when it writes
    report prose -- hold it to the same vocabulary rules. Only the
    filler/placeholder rules apply here: documentation legitimately repeats
    headings (CHANGELOG) and has no orientation contract."""
    if rel_path in FILLER_EXEMPT_DOCS:
        pytest.skip("this document names the banned words in order to ban them")
    findings = [
        f
        for f in lint_markdown((ROOT / rel_path).read_text(), require_intro=False)
        if f.rule in ("banned-phrase", "unfilled-placeholder")
    ]
    assert not findings, f"{rel_path}: " + "; ".join(str(f) for f in findings)


def test_every_skill_loads_the_writing_style_reference():
    """Every skill produces stakeholder-facing prose; each must point at the
    one style document so the deliverables don't drift apart (same pattern
    as the diagram-conventions test in test_skill_integrity.py)."""
    assert (ROOT / WRITING_STYLE_DOC).exists()
    for skill_md in sorted((ROOT / "skills").glob("*/SKILL.md")):
        assert WRITING_STYLE_DOC in skill_md.read_text(), (
            f"{skill_md.relative_to(ROOT)} does not load {WRITING_STYLE_DOC}"
        )


# ------------------------------------------------------- generated artifacts
discover = _load("pq_discover", "skills/aws-architecture-discovery/scripts/discover.py")
analyze_cost = _load("pq_analyze_cost", "skills/aws-cost-optimization/scripts/analyze_cost.py")
security_scan = _load("pq_security_scan", "skills/aws-security-review/scripts/security_scan.py")
traffic_analysis = _load("pq_traffic_analysis", "skills/aws-network-traffic-analysis/scripts/traffic_analysis.py")
collect_evidence = _load("pq_collect_evidence", "skills/aws-well-architected-review/scripts/collect_evidence.py")
analyze_organization = _load("pq_analyze_organization", "skills/aws-organizations-posture/scripts/analyze_organization.py")
dr_readiness = _load("pq_dr_readiness", "skills/aws-dr-readiness/scripts/dr_readiness.py")


def _rendered_reports() -> dict[str, str]:
    """Render every skill's report from minimal synthetic evidence --
    enough to produce each report's fixed prose, which is what the lint
    judges (findings tables carry quoted AWS data and are exempt)."""
    reports = {}

    reports["architecture-discovery"] = discover.build_report(
        {
            "AccountId": "123456789012",
            "Regions": {},
            "Global": {"DataStores": {"S3Buckets": [], "PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []}},
        },
        {},
    ).render_markdown()

    reports["cost-optimization"] = analyze_cost.build_report(
        {
            "CostReport": {
                "CostByService": [],
                "ReservationUtilization": {
                    "Total": {"UtilizationPercentage": "88.5", "UnusedHours": "120", "NetRISavings": "432.10"}
                },
                "SavingsPlansUtilization": {
                    "Total": {
                        "Utilization": {"UtilizationPercentage": "97.2", "UnusedCommitment": "14.00"},
                        "Savings": {"NetSavings": "210.00"},
                    }
                },
                "RightsizingRecommendations": [],
                "TrustedAdvisorCostChecks": [],
                "Anomalies": [],
                "Budgets": [],
            },
            "ComputeOptimizerEc2": {},
            "ComputeOptimizerEbs": {},
            "IdleResources": {},
        },
        "2024-01-01",
        "2024-03-01",
    ).render_markdown()

    reports["security-review"] = security_scan.build_report(
        {
            "Global": {
                "IamFindings": {
                    "ConsoleUsersWithoutMfa": [],
                    "AccessKeysToReview": [],
                    "RootAccountRisks": [],
                    "PasswordPolicySet": True,
                },
                "DataStores": {"PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []},
                "CloudTrail": {"Trails": [], "HasMultiRegionTrail": True, "HasLoggingTrail": True, "HasLogFileValidation": True},
            },
            "Regions": {
                "us-east-1": {
                    "Security": {
                        "GuardDuty": {"Enabled": True},
                        "SecurityHub": {"Enabled": True},
                        "GuardDutyFindings": [{"Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 5.0}],
                        "SecurityHubFindings": [],
                        "SecurityHubStandardsSummary": [],
                        "AccessAnalyzerFindings": [],
                        "ConfigRuleCompliance": [],
                        "ConfigRecorder": {"Recording": True},
                    },
                    "WideOpenSecurityGroups": [],
                    "Compute": {},
                }
            },
        }
    ).render_markdown()

    reports["network-traffic-analysis"] = traffic_analysis.build_report(
        {
            "Window": {"Start": "2024-01-01T00:00:00", "End": "2024-01-02T00:00:00"},
            "FlowLogAnalysis": {
                "top_talkers_by_bytes": [],
                "traffic_by_protocol": [],
                "rejected_traffic": [],
                "port_scan_candidates": [],
                "top_external_egress": [],
            },
            "NetworkFindings": [{"Type": "Recon:EC2/Portscan", "Severity": 5.0, "Resource": {"ResourceType": "Instance"}}],
        },
        "us-east-1",
        "/vpc/flowlogs",
    ).render_markdown()

    reports["well-architected-evidence"] = collect_evidence.build_report(
        {
            "Regions": {},
            "Global": {
                "Security": {
                    "IamFindings": {
                        "ConsoleUsersWithoutMfa": [],
                        "AccessKeysToReview": [],
                        "RootAccountRisks": [],
                        "PasswordPolicySet": True,
                    }
                },
                "DataStores": {},
                "Cost": {"Budgets": []},
                "CloudTrail": {"HasMultiRegionTrail": True, "HasLoggingTrail": True, "HasLogFileValidation": True},
            },
        },
        list(collect_evidence.PILLARS),
    ).render_markdown()

    reports["organizations-posture"] = analyze_organization.build_report(
        {
            "IsOrganizationsMember": True,
            "Organization": {"MasterAccountId": "123456789012", "FeatureSet": "ALL"},
            "Accounts": [{"Id": "111111111111", "Name": "prod", "Email": "prod@example.com", "Status": "ACTIVE"}],
            "ServiceControlPolicies": [],
            "AccountsWithoutScpCoverage": [],
            "DelegatedAdministrators": [],
            "GuardDutyOrganizationAdmin": None,
            "SecurityHubOrganizationAdmin": None,
        }
    ).render_markdown()

    reports["dr-readiness"] = dr_readiness.build_report(
        {
            "Summary": {
                "Backup": {
                    "PlanCount": 1,
                    "VaultCount": 1,
                    "PlansWithCrossRegionCopy": 0,
                    "ProtectedResourceCount": 3,
                    "RecentFailedJobs": 0,
                },
                "Rds": {"SingleAzInstances": [], "InstancesWithReadReplicas": [], "CrossRegionOrGlobalClusters": []},
                "S3": {"ReplicatedBuckets": [], "UnreplicatedBuckets": []},
                "Route53HealthChecks": [],
            }
        }
    ).render_markdown()

    return reports


RENDERED = _rendered_reports()


@pytest.mark.parametrize("name", sorted(RENDERED), ids=sorted(RENDERED))
def test_every_generated_report_passes_the_prose_lint(name):
    findings = lint_markdown(RENDERED[name])
    assert not findings, f"{name}: " + "; ".join(str(f) for f in findings)


@pytest.mark.parametrize("name", sorted(RENDERED), ids=sorted(RENDERED))
def test_every_generated_report_opens_with_an_orientation_paragraph(name):
    """Belt to the lint's braces: the orientation text must appear before
    the first section heading and actually say where to start."""
    md = RENDERED[name]
    before_first_section = md.split("\n## ")[0]
    assert "Start with" in before_first_section, (
        f"{name} does not tell the reader where to start before its first section"
    )


def test_security_report_severity_legend_lists_only_used_levels():
    md = RENDERED["security-review"]
    assert "**MEDIUM** = plan a fix this quarter" in md  # the one finding is severity 5.0
    assert "**CRITICAL**" not in md, "legend lists a severity level the report never uses"


def test_traffic_report_includes_severity_legend_for_guardduty_findings():
    md = RENDERED["network-traffic-analysis"]
    assert "Severity levels in this report:" in md
    assert "**MEDIUM** = plan a fix this quarter" in md


# ----------------------------------------------------- the lint CLI (bin/)
def test_lint_cli_fails_on_a_bad_report_and_passes_a_clean_one(tmp_path):
    bad = tmp_path / "a-bad.md"
    bad.write_text("# T\n\n## No Intro\n\nWe leverage robust synergy. TODO: numbers.\n")
    good = tmp_path / "b-good.md"
    good.write_text("# T\n\nCovers one account. Start with the summary.\n\n## Summary\n\n3 findings.\n")

    proc = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "lint-report-prose"), str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    # Sorted-order pass: the bad file is reported first, the clean one passes.
    assert proc.stdout.index("FAIL") < proc.stdout.index("ok  ")
    assert "banned-phrase" in proc.stdout
    assert "unfilled-placeholder" in proc.stdout
    assert "missing-orientation" in proc.stdout
    assert "b-good.md" in proc.stdout

    bad.unlink()
    proc = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "lint-report-prose"), str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0


def test_lint_cli_exits_nonzero_when_nothing_to_lint(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "lint-report-prose"), str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1


def test_finding_str_names_line_rule_and_detail():
    from shared.reporting.prose_lint import Finding

    assert str(Finding(7, "banned-phrase", "'robust' in: 'x'")) == "line 7: [banned-phrase] 'robust' in: 'x'"
