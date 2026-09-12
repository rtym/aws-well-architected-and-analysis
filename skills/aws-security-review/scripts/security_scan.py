#!/usr/bin/env python3
"""Assess AWS security posture: GuardDuty and Security Hub enablement +
findings, Security Hub standards (CIS/FSBP/PCI) control pass rates, IAM
Access Analyzer findings, AWS Config rule compliance, IAM hygiene (MFA,
stale keys, root account, password policy), and public/unencrypted S3
buckets and wide-open security groups -- then render a severity-ranked
Markdown/HTML/PDF report with charts.

Read-only. Every call is a Describe/List/Get; nothing here changes a
security control or remediates a finding.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions  # noqa: E402
from shared.awslib.collectors import cloudtrail, compute, data_stores, security, vpc  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Assess AWS security posture across GuardDuty, Security Hub, IAM, and network exposure.")
    parser.add_argument("--regions", default=None, help="Comma-separated regions (default: --region only)")
    parser.add_argument("--all-regions", action="store_true", help="Scan every region enabled for this account")
    return parser.parse_args(argv)


def collect(ctx, regions: list[str]) -> dict:
    data = {"Regions": {}, "Global": security.collect_global_security(ctx)}
    for region in regions:
        compute_data = compute.collect_region_compute(ctx, region)
        data["Regions"][region] = {
            "Security": security.collect_region_security(ctx, region),
            "WideOpenSecurityGroups": vpc.wide_open_security_groups(vpc.describe_security_groups(ctx, region)),
            "Compute": compute_data,
        }
    data["Global"]["DataStores"] = data_stores.collect_global_data_stores(ctx)
    # CloudTrail trails are visible account-wide from one region call.
    data["Global"]["CloudTrail"] = cloudtrail.cloudtrail_posture(ctx, regions[0])
    return data


def _standard_name(standards_arn: str) -> str:
    """"arn:aws:securityhub:::ruleset/cis-aws-foundations/v/1.2.0" -> "cis-aws-foundations v1.2.0"."""
    parts = standards_arn.split("/")
    if len(parts) >= 4 and parts[-2] == "v":
        return f"{parts[-3]} v{parts[-1]}"
    return standards_arn


def guardduty_severity_label(score: float) -> str:
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def build_report(data: dict) -> Report:
    report = Report(title="AWS Security Review", subtitle="GuardDuty, Security Hub, IAM, and network exposure findings")

    ct = data["Global"]["CloudTrail"]
    ct_lines = [
        f"- **Multi-region trail configured:** {'yes' if ct['HasMultiRegionTrail'] else 'NO -- gap'}",
        f"- **A trail is actively logging:** {'yes' if ct['HasLoggingTrail'] else 'NO -- gap'}",
        f"- **Log file validation enabled:** {'yes' if ct['HasLogFileValidation'] else 'no'}",
        f"- **Trails found:** {len(ct['Trails'])}",
    ]
    report.add_section("CloudTrail", "\n".join(ct_lines))

    iam_findings = data["Global"]["IamFindings"]
    iam_lines = [
        f"- **Console users without MFA:** {len(iam_findings['ConsoleUsersWithoutMfa'])}",
        f"- **Access keys to review (active, rotation age tracked):** {len(iam_findings['AccessKeysToReview'])}",
        f"- **Root account risks:** {', '.join(iam_findings['RootAccountRisks']) or 'none detected'}",
        f"- **Account password policy set:** {'yes' if iam_findings['PasswordPolicySet'] else 'no'}",
    ]
    report.add_section("IAM Hygiene", "\n".join(iam_lines))

    public_buckets = data["Global"]["DataStores"]["PubliclyAccessibleBuckets"]
    unencrypted_buckets = data["Global"]["DataStores"]["UnencryptedBuckets"]
    s3_rows = [{"Bucket": b["Name"], "Issue": "Public access not fully blocked"} for b in public_buckets]
    s3_rows += [{"Bucket": b["Name"], "Issue": "No default encryption configured"} for b in unencrypted_buckets]
    if s3_rows:
        report.add_section("S3 Exposure", findings_table(s3_rows, ["Bucket", "Issue"]))
    else:
        report.add_section("S3 Exposure", "No publicly-exposed or unencrypted S3 buckets detected.")

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    per_region_rows = []
    all_sh_findings = []
    all_gd_findings = []
    open_sg_total = 0

    for region, region_data in data["Regions"].items():
        sec = region_data["Security"]
        gd = sec["GuardDuty"]
        sh = sec["SecurityHub"]
        gd_findings = sec["GuardDutyFindings"]
        sh_findings = sec["SecurityHubFindings"]
        open_sgs = region_data["WideOpenSecurityGroups"]
        open_sg_total += len(open_sgs)

        for f in gd_findings:
            severity_counts[guardduty_severity_label(f.get("Severity", 0))] += 1
            all_gd_findings.append({**f, "_Region": region})
        for f in sh_findings:
            label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
            if label in severity_counts:
                severity_counts[label] += 1
            all_sh_findings.append({**f, "_Region": region})

        config_recorder = sec.get("ConfigRecorder", {})
        per_region_rows.append(
            {
                "Region": region,
                "GuardDuty": "enabled" if gd["Enabled"] else "NOT enabled",
                "Security Hub": "enabled" if sh.get("Enabled") else "NOT enabled",
                "Config recorder": "recording" if config_recorder.get("Recording") else "NOT recording",
                "GuardDuty findings": len(gd_findings),
                "Security Hub findings": len(sh_findings),
                "Open security groups": len(open_sgs),
            }
        )

    report.add_section("Regional Coverage", findings_table(
        per_region_rows,
        ["Region", "GuardDuty", "Security Hub", "Config recorder", "GuardDuty findings", "Security Hub findings", "Open security groups"],
    ))

    non_zero = {k: v for k, v in severity_counts.items() if v}
    if non_zero:
        sev_chart = charts.bar_chart(list(non_zero), list(non_zero.values()), title="Findings by severity (GuardDuty + Security Hub)", ylabel="Count")
        report.add_section("Finding Severity Distribution", f"![Severity distribution]({sev_chart})")

    if all_sh_findings:
        rows = [
            {
                "Region": f["_Region"],
                "Severity": f.get("Severity", {}).get("Label", "?"),
                "Title": f.get("Title", "?"),
                "Resource": (f.get("Resources") or [{}])[0].get("Id", "?"),
            }
            for f in sorted(all_sh_findings, key=lambda x: SEVERITY_ORDER.index(x.get("Severity", {}).get("Label", "INFORMATIONAL")) if x.get("Severity", {}).get("Label") in SEVERITY_ORDER else 99)[:40]
        ]
        report.add_section("Security Hub Findings (Active, High/Critical)", findings_table(rows, ["Region", "Severity", "Title", "Resource"]))

    if all_gd_findings:
        rows = [
            {
                "Region": f["_Region"],
                "Severity": guardduty_severity_label(f.get("Severity", 0)),
                "Type": f.get("Type", "?"),
            }
            for f in all_gd_findings[:40]
        ]
        report.add_section("GuardDuty Findings", findings_table(rows, ["Region", "Severity", "Type"]))

    standards_rows = []
    for region, region_data in data["Regions"].items():
        for s in region_data["Security"].get("SecurityHubStandardsSummary", []):
            pct = round(100 * s["EnabledControlCount"] / s["ControlCount"], 1) if s["ControlCount"] else 0
            standards_rows.append({"Region": region, "Standard": _standard_name(s["StandardsArn"]), "Enabled controls": f"{s['EnabledControlCount']}/{s['ControlCount']} ({pct}%)"})
    if standards_rows:
        report.add_section("Security Hub Standards Coverage", findings_table(standards_rows, ["Region", "Standard", "Enabled controls"]))

    config_rows = []
    for region, region_data in data["Regions"].items():
        for c in region_data["Security"].get("ConfigRuleCompliance", []):
            compliance = c.get("Compliance", {}).get("ComplianceType", "?")
            if compliance == "NON_COMPLIANT":
                config_rows.append({"Region": region, "Rule": c.get("ConfigRuleName", "?"), "Status": compliance})
    if config_rows:
        report.add_section("AWS Config -- Non-Compliant Rules", findings_table(config_rows, ["Region", "Rule", "Status"]))

    aa_rows = []
    for region, region_data in data["Regions"].items():
        for f in region_data["Security"].get("AccessAnalyzerFindings", []):
            aa_rows.append({"Region": region, "Resource type": f.get("resourceType", "?"), "Status": f.get("status", "?")})
    if aa_rows:
        report.add_section("IAM Access Analyzer -- Active Findings", findings_table(aa_rows, ["Region", "Resource type", "Status"]))

    if open_sg_total:
        sg_rows = []
        for region, region_data in data["Regions"].items():
            for sg in region_data["WideOpenSecurityGroups"]:
                sg_rows.append(
                    {
                        "Region": region,
                        "Group": sg["GroupId"],
                        "Port range": f"{sg.get('FromPort')}-{sg.get('ToPort')}",
                        "Protocol": sg.get("IpProtocol"),
                        "Open to": ", ".join(sg["OpenRanges"]),
                    }
                )
        report.add_section("Wide-Open Security Group Rules", findings_table(sg_rows, ["Region", "Group", "Port range", "Protocol", "Open to"]))

    imdsv1_rows = []
    plaintext_rows = []
    cert_rows = []
    for region, region_data in data["Regions"].items():
        comp = region_data.get("Compute", {})
        for i in comp.get("InstancesAllowingImdsv1", []):
            imdsv1_rows.append({"Region": region, "Instance": i.get("InstanceId"), "State": i.get("State", {}).get("Name")})
        for p in comp.get("PlaintextListeners", []):
            plaintext_rows.append({"Region": region, "Load balancer": p["LoadBalancerName"], "Port": p["Port"], "Protocol": p["Protocol"]})
        for c in comp.get("ExpiringCertificates", []):
            cert_rows.append({"Region": region, "Domain": c.get("DomainName"), "Expires": c.get("NotAfter"), "In use": c.get("InUse")})

    if imdsv1_rows:
        report.add_section(
            "EC2 Instances Not Enforcing IMDSv2",
            "Instances where the instance metadata service still accepts IMDSv1 (SSRF-exploitable credential theft path):\n\n"
            + findings_table(imdsv1_rows, ["Region", "Instance", "State"]),
        )
    if plaintext_rows:
        report.add_section("Load Balancer Listeners Without TLS", findings_table(plaintext_rows, ["Region", "Load balancer", "Port", "Protocol"]))
    if cert_rows:
        report.add_section("ACM Certificates Expired or Expiring Within 30 Days", findings_table(cert_rows, ["Region", "Domain", "Expires", "In use"]))

    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    regions = resolve_regions(ctx, args)

    data = collect(ctx, regions)

    if args.json_out:
        jsonutil.write(data, args.json_out)
        print(f"Raw security evidence JSON written to {args.json_out}")

    report = build_report(data)
    paths = report.save(args.output_dir, "security-review", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
