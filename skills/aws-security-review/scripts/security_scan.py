#!/usr/bin/env python3
"""Assess AWS security posture: GuardDuty, Security Hub, Inspector, and
Macie enablement + findings, Security Hub standards (CIS/FSBP/PCI) control
pass rates, IAM Access Analyzer findings, AWS Config rule compliance, IAM
hygiene (MFA, key age, root account, password policy), public/unencrypted
S3 buckets plus the account-level Block Public Access backstop, wide-open
and default security groups, EBS/RDS encryption and public-snapshot
exposure, KMS rotation, and Lambda function URLs without auth.

The evidence is scored with checks mapped to Security Hub controls
(`shared/analysis/security_checks.py`), correlated into attack paths, and
ranked into one priority list; the report leads with that analysis and
keeps the raw evidence tables below it, in Markdown/HTML/PDF.

Read-only. Every call is a Describe/List/Get; nothing here changes a
security control or remediates a finding.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from shared.analysis import checks as engine  # noqa: E402
from shared.analysis import security_checks  # noqa: E402
from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions  # noqa: E402
from shared.awslib.collectors import cloudtrail, compute, data_stores, security, vpc  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import (  # noqa: E402
    Report,
    ScoreArea,
    Scorecard,
    escape_text,
    findings_table,
    severity_legend,
    tone_for_score,
)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Assess AWS security posture across GuardDuty, Security Hub, IAM, and network exposure.")
    parser.add_argument("--regions", default=None, help="Comma-separated regions (default: --region only)")
    parser.add_argument("--all-regions", action="store_true", help="Scan every region enabled for this account")
    return parser.parse_args(argv)


def collect(ctx, regions: list[str]) -> dict:
    data = {"AccountId": None, "Regions": {}, "Global": security.collect_global_security(ctx)}
    try:
        data["AccountId"] = ctx.account_id()
    except (ClientError, BotoCoreError):
        # A label on the report, not evidence; the scan goes on without it.
        data["AccountId"] = None
    for region in regions:
        security_groups = vpc.describe_security_groups(ctx, region)
        rds_snapshots = data_stores.describe_rds_snapshots(ctx, region)
        data["Regions"][region] = {
            "Security": security.collect_region_security(ctx, region),
            "WideOpenSecurityGroups": vpc.wide_open_security_groups(security_groups),
            "DefaultSecurityGroupsWithRules": vpc.default_security_groups_with_rules(security_groups),
            "Compute": compute.collect_region_compute(ctx, region),
            "RdsExposure": data_stores.rds_exposure(data_stores.describe_rds_instances(ctx, region)),
            "PublicRdsSnapshots": data_stores.public_rds_snapshots(ctx, region, rds_snapshots)
            + data_stores.public_rds_cluster_snapshots(ctx, region),
        }
    data["Global"]["DataStores"] = data_stores.collect_global_data_stores(ctx)
    data["Global"]["AccountPublicAccessBlock"] = security.account_public_access_block(ctx)
    # CloudTrail trails are visible account-wide from one region call.
    data["Global"]["CloudTrail"] = cloudtrail.cloudtrail_posture(ctx, regions[0])
    return data


def analyze(data: dict) -> dict:
    return security_checks.analyze(data, security.guardduty_severity_label)


def evidence_with_analysis(data: dict, analysis: dict) -> dict:
    """The --json-out payload: the raw evidence plus the scored checks,
    attack paths, and priority actions, so the gap-analysis skill can cite
    them without recomputing anything."""
    return {**data, "Analysis": engine.to_dict(analysis["results"], analysis["paths"], analysis["actions"])}


def _standard_name(standards_arn: str) -> str:
    """"arn:aws:securityhub:::ruleset/cis-aws-foundations/v/1.2.0" -> "cis-aws-foundations v1.2.0"."""
    parts = standards_arn.split("/")
    if len(parts) >= 4 and parts[-2] == "v":
        return f"{parts[-3]} v{parts[-1]}"
    return standards_arn


def _port_range(rule: dict) -> str:
    """"all" for protocol -1 (AWS leaves FromPort/ToPort unset there, which
    used to render as "None-None"), a single port, or "from-to"."""
    if rule.get("IpProtocol") == "-1" or rule.get("FromPort") is None:
        return "all"
    if rule.get("FromPort") == rule.get("ToPort"):
        return str(rule.get("FromPort"))
    return f"{rule.get('FromPort')}-{rule.get('ToPort')}"


def _rule_risk(rule: dict) -> str:
    if security_checks.high_risk_ports_in(rule):
        return "High-risk port (EC2.19)"
    if security_checks.opens_unauthorized_port(rule):
        return "Not a web port (EC2.18)"
    return "Web port (80/443)"


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


# ------------------------------------------------------------ headline parts
def _scorecard(analysis: dict, region_count: int) -> Scorecard:
    overall = analysis["score"]
    by_domain = engine.scores_by_domain(analysis["results"])
    areas = []
    for domain in security_checks.DOMAINS:
        s = by_domain.get(domain)
        if s is None:
            continue
        detail = f"{s.passed} of {s.evaluated} passed" if s.evaluated else "no data"
        areas.append(ScoreArea(domain, s.score, detail))
    detail = f"{overall.passed} of {overall.evaluated} checks passed across {_plural(region_count, 'region')}"
    if overall.no_data:
        detail += f"; {overall.no_data} without data"
    return Scorecard(
        label="Security posture",
        score=overall.score,
        band=engine.band(overall.score),
        detail=detail,
        tone=tone_for_score(overall.score),
        areas=areas,
        method=(
            "Score = passed checks / checks with data, the method Security Hub uses for its "
            "security score. Severity does not weight it: read it with the critical and high counts."
        ),
    )


def _add_kpis(report: Report, data: dict, analysis: dict) -> None:
    results = analysis["results"]
    failed = [r for r in results if r.failed]
    critical = [r for r in failed if r.check.severity == "CRITICAL"]
    high = [r for r in failed if r.check.severity == "HIGH"]
    paths = analysis["paths"]
    gd_threats = sum(len(t.affected) for t in analysis["threats"] if t.reference == "GuardDuty")
    on, total = security_checks.detection_coverage(data)
    coverage = round(100 * on / total) if total else None

    report.add_kpi(
        "Critical gaps",
        len(critical),
        f"{_plural(sum(len(r.affected) for r in critical), 'affected item')}" if critical else "none failed",
        "bad" if critical else "good",
    )
    report.add_kpi(
        "High gaps",
        len(high),
        f"{_plural(sum(len(r.affected) for r in high), 'affected item')}" if high else "none failed",
        "warn" if high else "good",
    )
    report.add_kpi(
        "Attack paths",
        len(paths),
        "correlated exposures" if paths else "none found",
        "bad" if any(p.severity == "CRITICAL" for p in paths) else ("warn" if paths else "good"),
    )
    report.add_kpi("Active threats", gd_threats, "GuardDuty, high or critical", "bad" if gd_threats else "good")
    report.add_kpi(
        "Detection coverage",
        f"{coverage}%" if coverage is not None else "n/a",
        f"{on} of {total} service-region pairs on" if total else "no data",
        "neutral" if coverage is None else ("good" if coverage >= 90 else "warn" if coverage >= 60 else "bad"),
    )
    report.add_kpi("Regions scanned", len(data["Regions"]), ", ".join(list(data["Regions"])[:3]) + ("..." if len(data["Regions"]) > 3 else ""))


def _executive_summary(data: dict, analysis: dict) -> str:
    results = analysis["results"]
    overall = analysis["score"]
    failed = [r for r in results if r.failed]
    critical = sum(1 for r in failed if r.check.severity == "CRITICAL")
    high = sum(1 for r in failed if r.check.severity == "HIGH")
    lines = []
    if overall.score is None:
        lines.append("- **No check had data to evaluate.** Confirm the scan's permissions (see PERMISSIONS.md) and rerun.")
    else:
        lines.append(
            f"- **Posture score {overall.score}/100 ({engine.band(overall.score)}):** "
            f"{overall.passed} of {overall.evaluated} checks passed across {_plural(len(data['Regions']), 'region')}."
        )
    if critical or high:
        lines.append(f"- **{critical} critical and {high} high-severity checks failed.** The priority list below orders the fixes.")
    elif overall.score is not None:
        lines.append("- **No critical or high-severity check failed.**")
    paths = analysis["paths"]
    if paths:
        worst = paths[0]
        lines.append(
            f"- **{_plural(len(paths), 'attack path')}** link separate gaps into a direct route to compromise. "
            f"The most severe: {escape_text(worst.title)} ({engine.scope_text(worst.affected)})."
        )
    gd_threats = [t for t in analysis["threats"] if t.reference == "GuardDuty"]
    if gd_threats:
        count = sum(len(t.affected) for t in gd_threats)
        lines.append(
            f"- **GuardDuty reports {_plural(count, 'high or critical finding')}** that "
            f"{'needs' if count == 1 else 'need'} investigation now, ahead of configuration work."
        )
    if analysis["actions"]:
        first = analysis["actions"][0]
        lines.append(f"- **Start with:** {escape_text(first.action)}.")
    by_domain = {d: s for d, s in engine.scores_by_domain(results).items() if s.score is not None}
    if len(by_domain) > 1:
        weakest = min(by_domain, key=lambda d: by_domain[d].score)
        strongest = max(by_domain, key=lambda d: by_domain[d].score)
        if by_domain[weakest].score != by_domain[strongest].score:
            lines.append(
                f"- **Weakest area:** {weakest} ({by_domain[weakest].score}/100). "
                f"**Strongest:** {strongest} ({by_domain[strongest].score}/100)."
            )
    if not failed and not paths and not gd_threats and overall.score is not None:
        lines.append("- Nothing in this scan needs action now; rerun it after major changes or on a schedule.")
    return "\n".join(lines)


def _priority_actions(actions: list[engine.Action]) -> str:
    if not actions:
        return "No failed checks, attack paths, or open high-severity threats. Nothing to prioritize."
    rows = [
        {
            "#": a.priority,
            "Severity": a.severity,
            # The second line (rendered in italics) says what was found.
            "Action": f"{a.action}\n_{a.why}_",
            "Scope": a.scope,
            "Ref": a.reference,
            "Effort": a.effort,
        }
        for a in actions
    ]
    return (
        "The ten most important fixes, most severe first, each with what was found under it. At "
        "equal severity an attack path comes before an active threat, and both before a single "
        "failed check; exposed resources come before gaps in visibility. Effort is a rough guide: "
        "Low is a setting change, High means migrating data or resources.\n\n"
        + findings_table(rows, ["#", "Severity", "Action", "Scope", "Ref", "Effort"])
    )


def _attack_path_body(path: engine.AttackPath) -> str:
    builds_on = ", ".join(
        security_checks.CHECKS_BY_ID[c].reference for c in path.builds_on if c in security_checks.CHECKS_BY_ID
    )
    rows = [{"Region": a.region, "Resource": a.resource, "Detail": a.detail} for a in path.affected[:25]]
    more = f"\n\n_{len(path.affected) - 25} more not shown; see the JSON evidence._" if len(path.affected) > 25 else ""
    return (
        f"{findings_table([{'Severity': path.severity, 'Combines': builds_on, 'Effort': path.effort}], ['Severity', 'Combines', 'Effort'])}\n\n"
        f"{escape_text(path.why)}\n\n"
        f"**Fix:** {escape_text(path.remediation)}.\n\n"
        + findings_table(rows, ["Region", "Resource", "Detail"])
        + more
    )


def _affected_text(result: engine.CheckResult) -> str:
    if result.status != engine.FAIL:
        return "--"
    return engine.scope_text(result.affected)


def _check_tables(analysis: dict) -> list[tuple[str, str]]:
    sections = []
    for domain in security_checks.DOMAINS:
        domain_results = [r for r in analysis["results"] if r.check.domain == domain]
        if not domain_results:
            continue
        ordered = sorted(
            domain_results,
            key=lambda r: ({engine.FAIL: 0, engine.NO_DATA: 1, engine.PASS: 2}[r.status], engine.SEVERITY_RANK[r.check.severity]),
        )
        rows = [
            {
                "Status": r.status,
                "Severity": r.check.severity,
                "Check": r.check.title,
                "Control": r.check.reference,
                "Affected": _affected_text(r),
            }
            for r in ordered
        ]
        notes = [f"_{escape_text(r.note)}_" for r in ordered if r.note]
        body = findings_table(rows, ["Status", "Severity", "Check", "Control", "Affected"])
        if notes:
            body += "\n\n" + "\n\n".join(notes)
        sections.append((domain, body))
    return sections


# ---------------------------------------------------------------- the report
def build_report(data: dict, analysis: dict | None = None) -> Report:
    analysis = analysis or analyze(data)
    # Region names come from CLI input/DescribeRegions; escaped because the
    # intro is a section-body-style sink (not escaped by Report, by contract).
    regions = escape_text(", ".join(data["Regions"])) or "none"
    report = Report(
        title="AWS Security Review",
        subtitle="Posture checks, attack paths, and threat findings",
        meta={"Account": data.get("AccountId") or "unknown", "Regions": ", ".join(data["Regions"]) or "none"},
        intro=(
            f"This report scores the security posture of one AWS account across region(s) "
            f"{regions} with {len(security_checks.CATALOG)} checks mapped to Security Hub controls, links gaps that make each "
            "other worse into attack paths, and ranks every fix in one list. Start with the "
            "Executive Summary and Priority Actions; the Evidence Detail sections at the end "
            "list every affected resource."
        ),
    )
    report.scorecard = _scorecard(analysis, len(data["Regions"]))
    _add_kpis(report, data, analysis)

    report.add_section("Executive Summary", _executive_summary(data, analysis))
    report.add_section("Priority Actions", _priority_actions(analysis["actions"]))

    paths = analysis["paths"]
    if paths:
        report.add_section(
            "Attack Paths",
            "Each attack path joins two or more findings on the same resource or region that are "
            "worse together than apart. They are concrete leads to act on, not proof that an attack "
            "happened.",
        )
        for path in paths:
            report.add_section(path.title, _attack_path_body(path), level=3)

    counts = engine.severity_counts(analysis["results"])
    check_intro = (
        "Every check, failures first. **Control** is the Security Hub control the check implements; "
        "\"(related)\" marks a check that tests the same risk more narrowly. NO DATA means the scan "
        "couldn't read the evidence or found nothing to evaluate.\n\n"
    )
    if any(counts.values()):
        chart = charts.severity_chart(counts, title="Failed checks by severity")
        check_intro += f"![Failed checks by severity]({chart})\n\n{severity_legend([s for s, n in counts.items() if n])}"
    report.add_section("Control Checks", check_intro)
    for domain, body in _check_tables(analysis):
        report.add_section(domain, body, level=3)

    _coverage_section(report, data)
    _threat_sections(report, data)
    _evidence_sections(report, data)
    report.add_section("Method and Scope", _method_text())
    return report


def _coverage_section(report: Report, data: dict) -> None:
    rows = []
    for region, region_data in data["Regions"].items():
        sec = region_data["Security"]
        analyzers = sec.get("AccessAnalyzers")
        rows.append(
            {
                "Region": region,
                "GuardDuty": "enabled" if sec["GuardDuty"]["Enabled"] else "NOT enabled",
                "Security Hub": "enabled" if sec.get("SecurityHub", {}).get("Enabled") else "NOT enabled",
                "Inspector": "enabled" if sec.get("Inspector2", {}).get("Enabled") else "NOT enabled",
                "Macie": "enabled" if sec.get("Macie", {}).get("Enabled") else "NOT enabled",
                "Config recorder": "recording" if sec.get("ConfigRecorder", {}).get("Recording") else "NOT recording",
                "Access Analyzer": "unknown" if analyzers is None else ("enabled" if analyzers else "NOT enabled"),
            }
        )
    report.add_section(
        "Detection Coverage",
        "Which detection services are on in each scanned region. A service that is off can't "
        "report anything, so a quiet region with gaps here is unmonitored, not clean.\n\n"
        + findings_table(rows, ["Region", "GuardDuty", "Security Hub", "Inspector", "Macie", "Config recorder", "Access Analyzer"]),
    )


def _threat_sections(report: Report, data: dict) -> None:
    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    per_region_rows = []
    all_sh_findings = []
    all_gd_findings = []
    for region, region_data in data["Regions"].items():
        sec = region_data["Security"]
        gd_findings = sec["GuardDutyFindings"]
        sh_findings = sec["SecurityHubFindings"]
        for f in gd_findings:
            severity_counts[security.guardduty_severity_label(f.get("Severity", 0))] += 1
            all_gd_findings.append({**f, "_Region": region})
        for f in sh_findings:
            label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
            if label in severity_counts:
                severity_counts[label] += 1
            all_sh_findings.append({**f, "_Region": region})
        per_region_rows.append(
            {
                "Region": region,
                "GuardDuty findings": len(gd_findings),
                "Security Hub findings": len(sh_findings),
                "Open security group rules": len(region_data["WideOpenSecurityGroups"]),
            }
        )

    body = (
        "Active detections from GuardDuty (unarchived) and Security Hub (active, CRITICAL and "
        "HIGH only). These need investigation, not only configuration changes.\n\n"
        + findings_table(per_region_rows, ["Region", "GuardDuty findings", "Security Hub findings", "Open security group rules"])
    )
    non_zero = {k: v for k, v in severity_counts.items() if v}
    if non_zero:
        chart = charts.severity_chart(non_zero, title="Service findings by severity (GuardDuty + Security Hub)")
        body += f"\n\n![Severity distribution]({chart})\n\n{severity_legend(non_zero)}"
    else:
        body += "\n\nNo open GuardDuty or Security Hub findings in the scanned regions."
    report.add_section("Threat Findings", body)

    if all_gd_findings:
        # Most severe first across every region, so the 40-row cap drops
        # the least severe findings rather than whichever region came last.
        most_severe_first = sorted(all_gd_findings, key=lambda f: f.get("Severity", 0), reverse=True)
        rows = [
            {
                "Region": f["_Region"],
                "Severity": security.guardduty_severity_label(f.get("Severity", 0)),
                "Type": f.get("Type", "?"),
                "Resource": (f.get("Resource") or {}).get("ResourceType", ""),
            }
            for f in most_severe_first[:40]
        ]
        report.add_section("GuardDuty Findings", findings_table(rows, ["Region", "Severity", "Type", "Resource"]), level=3)

    if all_sh_findings:
        rows = [
            {
                "Region": f["_Region"],
                "Severity": f.get("Severity", {}).get("Label", "?"),
                "Title": f.get("Title", "?"),
                "Resource": (f.get("Resources") or [{}])[0].get("Id", "?"),
            }
            for f in sorted(
                all_sh_findings,
                key=lambda x: SEVERITY_ORDER.index(x.get("Severity", {}).get("Label", "INFORMATIONAL"))
                if x.get("Severity", {}).get("Label") in SEVERITY_ORDER
                else 99,
            )[:40]
        ]
        report.add_section(
            "Security Hub Findings (Active, High/Critical)", findings_table(rows, ["Region", "Severity", "Title", "Resource"]), level=3
        )


def _evidence_sections(report: Report, data: dict) -> None:
    report.add_section(
        "Evidence Detail",
        "The collected evidence behind the checks, area by area, with every affected resource.",
    )

    ct = data["Global"]["CloudTrail"]
    ct_lines = [
        f"- **Multi-region trail configured:** {'yes' if ct['HasMultiRegionTrail'] else 'NO -- gap'}",
        f"- **A trail is actively logging:** {'yes' if ct['HasLoggingTrail'] else 'NO -- gap'}",
        f"- **A multi-region trail is logging (CloudTrail.1):** "
        f"{'yes' if ct.get('HasLoggingMultiRegionTrail', ct['HasMultiRegionTrail'] and ct['HasLoggingTrail']) else 'NO -- gap'}",
        f"- **Log file validation enabled:** {'yes' if ct['HasLogFileValidation'] else 'no'}",
        f"- **Trails found:** {len(ct['Trails'])}",
    ]
    report.add_section("CloudTrail", "\n".join(ct_lines), level=3)

    iam_findings = data["Global"]["IamFindings"]
    iam_lines = [
        f"- **Console users without MFA:** {len(iam_findings['ConsoleUsersWithoutMfa'])}",
        f"- **Active access keys older than 90 days:** {len(iam_findings['AccessKeysToReview'])}",
        f"- **Root account risks:** {', '.join(iam_findings['RootAccountRisks']) or 'none detected'}",
        f"- **Account password policy set:** {'yes' if iam_findings['PasswordPolicySet'] else 'no'}",
    ]
    iam_body = "\n".join(iam_lines)
    if iam_findings["ConsoleUsersWithoutMfa"]:
        iam_body += "\n\n" + findings_table(
            [{"User": u, "Issue": "Console password without MFA"} for u in iam_findings["ConsoleUsersWithoutMfa"]],
            ["User", "Issue"],
        )
    if iam_findings["AccessKeysToReview"]:
        iam_body += "\n\n" + findings_table(
            [
                {"User": k.get("user"), "Key": k.get("key"), "Last rotated": k.get("last_rotated"), "Age (days)": k.get("age_days", "?")}
                for k in iam_findings["AccessKeysToReview"]
            ],
            ["User", "Key", "Last rotated", "Age (days)"],
        )
    report.add_section("IAM Hygiene", iam_body, level=3)

    account_bpa = data["Global"].get("AccountPublicAccessBlock")
    if account_bpa is None:
        bpa_line = "NOT configured -- gap (per-bucket settings are the only guard)"
    elif all(account_bpa.get(k, False) for k in security_checks.BPA_SETTINGS):
        bpa_line = "all four settings enabled"
    else:
        bpa_line = "partially enabled -- gap"
    s3_intro = f"- **Account-level S3 Block Public Access:** {bpa_line}\n\n"

    public_buckets = data["Global"]["DataStores"]["PubliclyAccessibleBuckets"]
    unencrypted_buckets = data["Global"]["DataStores"]["UnencryptedBuckets"]
    s3_rows = [{"Bucket": b["Name"], "Issue": "Public access not fully blocked"} for b in public_buckets]
    s3_rows += [{"Bucket": b["Name"], "Issue": "No default encryption configured"} for b in unencrypted_buckets]
    if s3_rows:
        report.add_section("S3 Exposure", s3_intro + findings_table(s3_rows, ["Bucket", "Issue"]), level=3)
    else:
        report.add_section("S3 Exposure", s3_intro + "No publicly-exposed or unencrypted S3 buckets detected.", level=3)

    standards_rows = []
    for region, region_data in data["Regions"].items():
        for s in region_data["Security"].get("SecurityHubStandardsSummary", []):
            pct = round(100 * s["EnabledControlCount"] / s["ControlCount"], 1) if s["ControlCount"] else 0
            standards_rows.append({"Region": region, "Standard": _standard_name(s["StandardsArn"]), "Enabled controls": f"{s['EnabledControlCount']}/{s['ControlCount']} ({pct}%)"})
    if standards_rows:
        report.add_section("Security Hub Standards Coverage", findings_table(standards_rows, ["Region", "Standard", "Enabled controls"]), level=3)

    config_rows = []
    for region, region_data in data["Regions"].items():
        for c in region_data["Security"].get("ConfigRuleCompliance", []):
            compliance = c.get("Compliance", {}).get("ComplianceType", "?")
            if compliance == "NON_COMPLIANT":
                config_rows.append({"Region": region, "Rule": c.get("ConfigRuleName", "?"), "Status": compliance})
    if config_rows:
        report.add_section("AWS Config -- Non-Compliant Rules", findings_table(config_rows, ["Region", "Rule", "Status"]), level=3)

    aa_rows = []
    for region, region_data in data["Regions"].items():
        for f in region_data["Security"].get("AccessAnalyzerFindings", []):
            aa_rows.append(
                {
                    "Region": region,
                    "Finding type": f.get("findingType", "ExternalAccess"),
                    "Resource type": f.get("resourceType", "?"),
                    "Resource": f.get("resource", "?"),
                }
            )
    if aa_rows:
        report.add_section(
            "IAM Access Analyzer -- Active Findings",
            findings_table(aa_rows, ["Region", "Finding type", "Resource type", "Resource"]),
            level=3,
        )

    sg_rows = []
    for region, region_data in data["Regions"].items():
        for sg in region_data["WideOpenSecurityGroups"]:
            sg_rows.append(
                {
                    "Region": region,
                    "Group": sg["GroupId"],
                    "Port range": _port_range(sg),
                    "Protocol": sg.get("IpProtocol"),
                    "Open to": ", ".join(sg["OpenRanges"]),
                    "Risk": _rule_risk(sg),
                }
            )
    if sg_rows:
        sg_rows.sort(key=lambda r: {"High-risk port (EC2.19)": 0, "Not a web port (EC2.18)": 1}.get(r["Risk"], 2))
        report.add_section(
            "Wide-Open Security Group Rules",
            "Inbound rules open to 0.0.0.0/0 or ::/0, high-risk ports first. EC2.19's high-risk "
            "list covers administration and database ports (22, 3389, 3306, 5432, 1433, 9200, and "
            "more); EC2.18 allows only 80 and 443 by default.\n\n"
            + findings_table(sg_rows, ["Region", "Group", "Port range", "Protocol", "Open to", "Risk"]),
            level=3,
        )

    encryption_rows = []
    public_ebs_rows = []
    kms_rows = []
    for region, region_data in data["Regions"].items():
        sec = region_data["Security"]
        by_default = sec.get("EbsEncryptionByDefault")
        unencrypted_vols = sec.get("UnencryptedEbsVolumes", [])
        public_snaps = sec.get("PublicEbsSnapshots", [])
        kms_keys = sec.get("KmsKeysWithoutRotation", [])
        encryption_rows.append(
            {
                "Region": region,
                "EBS encryption by default": {True: "on", False: "OFF -- gap"}.get(by_default, "unknown"),
                "Unencrypted EBS volumes": len(unencrypted_vols),
                "Public EBS snapshots": len(public_snaps),
                "KMS keys without rotation": len(kms_keys),
            }
        )
        for s in public_snaps:
            public_ebs_rows.append({"Region": region, "Snapshot": s.get("SnapshotId"), "Volume": s.get("VolumeId")})
        for k in kms_keys:
            kms_rows.append({"Region": region, "Key": k.get("KeyId"), "Description": k.get("Description", "")})

    encryption_body = (
        "Encryption-at-rest posture per region. \"EBS encryption by default\" "
        "is the regional switch that encrypts every new volume automatically; "
        "a public snapshot is restorable by any AWS account.\n\n"
        + findings_table(
            encryption_rows,
            ["Region", "EBS encryption by default", "Unencrypted EBS volumes", "Public EBS snapshots", "KMS keys without rotation"],
        )
    )
    if public_ebs_rows:
        encryption_body += "\n\n**Publicly restorable EBS snapshots:**\n\n" + findings_table(
            public_ebs_rows, ["Region", "Snapshot", "Volume"]
        )
    if kms_rows:
        encryption_body += (
            "\n\n**Customer-managed KMS keys with automatic rotation off:**\n\n"
            + findings_table(kms_rows, ["Region", "Key", "Description"])
        )
    report.add_section("Encryption Posture (EBS and KMS)", encryption_body, level=3)

    rds_rows = []
    for region, region_data in data["Regions"].items():
        exposure = region_data.get("RdsExposure", {})
        for i in exposure.get("PubliclyAccessible", []):
            rds_rows.append({"Region": region, "Instance": i.get("DBInstanceIdentifier"), "Engine": i.get("Engine"), "Issue": "Publicly accessible"})
        for i in exposure.get("Unencrypted", []):
            rds_rows.append({"Region": region, "Instance": i.get("DBInstanceIdentifier"), "Engine": i.get("Engine"), "Issue": "Storage not encrypted"})
        for s in region_data.get("PublicRdsSnapshots", []):
            rds_rows.append({"Region": region, "Instance": s.get("DBSnapshotIdentifier"), "Engine": s.get("Engine"), "Issue": "Snapshot shared publicly"})
    if rds_rows:
        report.add_section("RDS Exposure", findings_table(rds_rows, ["Region", "Instance", "Engine", "Issue"]), level=3)

    lambda_url_rows = []
    for region, region_data in data["Regions"].items():
        for f in region_data["Security"].get("LambdaUrlsWithoutAuth", []):
            lambda_url_rows.append({"Region": region, "Function": f.get("FunctionName"), "URL": f.get("FunctionUrl")})
    if lambda_url_rows:
        report.add_section(
            "Lambda Function URLs Without Authentication",
            "Function URLs with auth type NONE accept unsigned requests from "
            "anyone on the internet:\n\n"
            + findings_table(lambda_url_rows, ["Region", "Function", "URL"]),
            level=3,
        )

    default_sg_rows = []
    for region, region_data in data["Regions"].items():
        for sg in region_data.get("DefaultSecurityGroupsWithRules", []):
            default_sg_rows.append(
                {
                    "Region": region,
                    "Group": sg.get("GroupId"),
                    "VPC": sg.get("VpcId"),
                    "Ingress rules": sg.get("IngressRules"),
                    "Egress rules": sg.get("EgressRules"),
                }
            )
    if default_sg_rows:
        report.add_section(
            "Default Security Groups Allowing Traffic",
            "A VPC's default security group should have no rules, so a "
            "resource launched without an explicit group gets no network "
            "access by accident:\n\n"
            + findings_table(default_sg_rows, ["Region", "Group", "VPC", "Ingress rules", "Egress rules"]),
            level=3,
        )

    imdsv1_rows = []
    plaintext_rows = []
    cert_rows = []
    for region, region_data in data["Regions"].items():
        comp = region_data.get("Compute", {})
        for i in comp.get("InstancesAllowingImdsv1", []):
            imdsv1_rows.append(
                {
                    "Region": region,
                    "Instance": i.get("InstanceId"),
                    "State": i.get("State", {}).get("Name"),
                    "Public IP": i.get("PublicIpAddress") or "--",
                }
            )
        for p in comp.get("PlaintextListeners", []):
            plaintext_rows.append({"Region": region, "Load balancer": p["LoadBalancerName"], "Port": p["Port"], "Protocol": p["Protocol"]})
        for c in comp.get("ExpiringCertificates", []):
            cert_rows.append({"Region": region, "Domain": c.get("DomainName"), "Expires": c.get("NotAfter"), "In use": c.get("InUse")})

    if imdsv1_rows:
        report.add_section(
            "EC2 Instances Not Enforcing IMDSv2",
            "Instances where the instance metadata service still accepts IMDSv1 (SSRF-exploitable credential theft path):\n\n"
            + findings_table(imdsv1_rows, ["Region", "Instance", "State", "Public IP"]),
            level=3,
        )
    if plaintext_rows:
        report.add_section("Load Balancer Listeners Without TLS", findings_table(plaintext_rows, ["Region", "Load balancer", "Port", "Protocol"]), level=3)
    if cert_rows:
        report.add_section("ACM Certificates Expired or Expiring Within 30 Days", findings_table(cert_rows, ["Region", "Domain", "Expires", "In use"]), level=3)


def _method_text() -> str:
    return "\n".join(
        [
            f"- **Checks.** {len(security_checks.CATALOG)} deterministic checks read the evidence collected in this run. Each names "
            "the Security Hub control it implements; checks without a control carry a severity this "
            "plugin assigns, listed in the skill's severity reference.",
            "- **Score.** Passed checks divided by checks with data, the method Security Hub uses for "
            "its security score. A check fails when any resource in any scanned region fails it.",
            "- **Attack paths.** Correlations across checks (an internet-reachable instance that also "
            "accepts IMDSv1, exposure in a region without GuardDuty). They show where gaps compound.",
            "- **Findings in scope.** GuardDuty findings are unarchived only; Security Hub findings "
            "are active CRITICAL and HIGH only. MEDIUM and LOW Security Hub findings are left out.",
            "- **Point in time.** The report reflects the account when it was generated, and only "
            "the regions listed above.",
        ]
    )


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    regions = resolve_regions(ctx, args)

    data = collect(ctx, regions)
    analysis = analyze(data)

    if args.json_out:
        jsonutil.write(evidence_with_analysis(data, analysis), args.json_out)
        print(f"Security evidence and analysis JSON written to {args.json_out}")

    report = build_report(data, analysis)
    paths = report.save(args.output_dir, "security-review", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
