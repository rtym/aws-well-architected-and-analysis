#!/usr/bin/env python3
"""Collect AWS-account evidence for a Well-Architected Framework pillar
review (Operational Excellence, Security, Reliability, Performance
Efficiency, Cost Optimization, Sustainability) and render a Markdown/HTML/PDF
evidence pack per pillar. This script gathers RAW EVIDENCE ONLY -- Claude
reads references/pillars/<pillar>.md (the question/best-practice catalogue)
alongside this evidence to produce the actual risk-rated findings; the two
are deliberately kept separate (see SKILL.md).

Read-only. Optionally cross-references a real AWS Well-Architected Tool
workload (--workload-id) if the account has one defined.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from shared.analysis import access  # noqa: E402
from shared.analysis import checks as engine  # noqa: E402
from shared.analysis import security_checks  # noqa: E402
from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions  # noqa: E402
from shared.awslib.collectors import (  # noqa: E402
    backup,
    cloudtrail,
    compute,
    containers,
    cost,
    data_stores,
    observability,
    quotas,
    security,
    vpc,
    well_architected,
)
from shared.reporting import jsonutil  # noqa: E402
from shared.reporting.report import Report, escape_text, findings_table  # noqa: E402

PILLARS = (
    "operational-excellence",
    "security",
    "reliability",
    "performance-efficiency",
    "cost-optimization",
    "sustainability",
)


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Collect AWS evidence for a Well-Architected Framework pillar review.")
    parser.add_argument(
        "--pillar",
        choices=[*PILLARS, "all"],
        default="all",
        help="Which pillar to collect evidence for (default: all)",
    )
    parser.add_argument("--regions", default=None, help="Comma-separated regions (default: --region only)")
    parser.add_argument("--all-regions", action="store_true", help="Scan every region enabled for this account")
    parser.add_argument("--workload-id", default=None, help="Existing AWS Well-Architected Tool workload ID to cross-reference")
    return parser.parse_args(argv)


def collect(ctx, regions: list[str], workload_id: str | None) -> dict:
    """One pass over every collector every pillar needs; the report layer
    picks out the fields relevant to whichever pillar(s) were requested."""
    evidence = {"Regions": {}, "Global": {}}
    for region in regions:
        evidence["Regions"][region] = {
            "Network": vpc.collect_region_network(ctx, region),
            "Compute": compute.collect_region_compute(ctx, region),
            "Containers": containers.collect_region_containers(ctx, region),
            "DataStores": data_stores.collect_region_data_stores(ctx, region),
            "Security": security.collect_region_security(ctx, region),
            "Backup": backup.collect_region_backup(ctx, region),
            "Observability": observability.collect_region_observability(ctx, region),
            "Quotas": quotas.common_quota_values(ctx, region),
        }
    evidence["Global"]["Security"] = security.collect_global_security(ctx)
    evidence["Global"]["DataStores"] = data_stores.collect_global_data_stores(ctx)
    evidence["Global"]["Cost"] = cost.collect_cost_report(
        ctx, *_default_cost_window()
    )
    evidence["Global"]["CloudTrail"] = cloudtrail.cloudtrail_posture(ctx, regions[0])
    if workload_id:
        evidence["Workload"] = well_architected.collect_workload_snapshot(ctx, regions[0], workload_id)
    # Calls the run was denied: a zero count behind one of these is unread.
    evidence[access.KEY] = access.denied_calls(ctx)
    return evidence


def _default_cost_window() -> tuple[str, str]:
    """UTC-based, matching how Cost Explorer interprets TimePeriod -- see
    the same note in aws-cost-optimization's `date_range()`."""
    import datetime

    end = datetime.datetime.now(datetime.timezone.utc).date()
    start = end - datetime.timedelta(days=90)
    return start.isoformat(), end.isoformat()


PILLAR_EVIDENCE_SUMMARY = {
    "operational-excellence": lambda ev, region_data: [
        f"- CloudWatch/Config visibility: {len(region_data['Security'].get('ConfigRuleCompliance', []))} Config rule evaluations found, Config recorder {'recording' if region_data['Security'].get('ConfigRecorder', {}).get('Recording') else 'NOT recording'}",
        f"- ECS/EKS workloads (deploy automation surface): {len(region_data['Containers']['EcsClusters'])} ECS clusters, {len(region_data['Containers']['EksClusters'])} EKS clusters",
        f"- Lambda functions (event-driven/IaC-friendly compute): {len(region_data['DataStores']['LambdaFunctions'])}",
        f"- CloudWatch alarms: {len(region_data['Observability']['Alarms'])} total, {len(region_data['Observability']['AlarmsWithNoActions'])} with no notification action, {len(region_data['Observability']['Dashboards'])} dashboards",
    ],
    "security": lambda ev, region_data: [
        f"- GuardDuty enabled: {region_data['Security']['GuardDuty']['Enabled']}",
        f"- Security Hub enabled: {region_data['Security']['SecurityHub'].get('Enabled', False)}",
        f"- Wide-open security group rules: {len(region_data['Network']['WideOpenSecurityGroupRules'])}",
        f"- IAM Access Analyzer active findings: {len(region_data['Security'].get('AccessAnalyzerFindings', []))}",
        f"- EC2 instances not enforcing IMDSv2: {len(region_data['Compute'].get('InstancesAllowingImdsv1', []))}",
        f"- Load balancer listeners without TLS: {len(region_data['Compute'].get('PlaintextListeners', []))}",
        f"- ACM certificates expired or expiring within 30 days: {len(region_data['Compute'].get('ExpiringCertificates', []))}",
    ],
    "reliability": lambda ev, region_data: [
        f"- Auto Scaling groups: {len(region_data['Compute']['AutoScalingGroups'])}",
        f"- Load balancers (ALB/NLB + classic): {len(region_data['Compute']['LoadBalancersV2']) + len(region_data['Compute']['ClassicLoadBalancers'])}",
        f"- Multi-AZ signal -- RDS instances: {len(region_data['DataStores']['RdsInstances'])}, manual snapshots: {len(region_data['DataStores']['RdsManualSnapshots'])}",
        f"- NAT gateways (single point of failure risk if 1 per VPC): {len(region_data['Network']['NatGateways'])}",
        f"- CloudWatch alarms monitoring this region: {len(region_data['Observability']['Alarms'])} ({len(region_data['Observability']['AlarmsInAlarmState'])} currently in ALARM state)",
        f"- AWS Backup plans covering this region: {len(region_data['Backup']['BackupPlans'])} ({len(region_data['Backup']['PlansWithCrossRegionCopy'])} with cross-region copy), {len(region_data['Backup']['FailedJobsRecent'])} recent failed jobs",
        f"- Service Quota headroom checked for: {', '.join(q['Label'] for q in region_data['Quotas']) or 'no quota data returned'}",
    ],
    "performance-efficiency": lambda ev, region_data: [
        f"- EC2 instances: {len(region_data['Compute']['Instances'])}",
        f"- VPC endpoints (reduces NAT/internet hairpin latency): {len(region_data['Network']['VpcEndpoints'])}",
        f"- ElastiCache clusters: {len(region_data['DataStores']['ElastiCacheClusters'])}",
        f"- DynamoDB tables: {len(region_data['DataStores']['DynamoDbTables'])}",
    ],
    "cost-optimization": lambda ev, region_data: [
        f"- Unattached EBS volumes: {len(region_data['Compute']['UnattachedVolumes'])}",
        f"- Unassociated Elastic IPs: {len(region_data['Compute']['UnassociatedEips'])}",
        f"- Stopped EC2 instances (still billed for EBS): {len(region_data['Compute']['StoppedInstances'])}",
    ],
    "sustainability": lambda ev, region_data: [
        f"- Stopped instances retaining attached storage: {len(region_data['Compute']['StoppedInstances'])}",
        f"- Unattached EBS volumes (wasted provisioned capacity): {len(region_data['Compute']['UnattachedVolumes'])}",
        f"- Manual RDS snapshots retained indefinitely: {len(region_data['DataStores']['RdsManualSnapshots'])}",
    ],
}


def security_bundle(evidence: dict) -> dict:
    """Reshape the evidence pack into the bundle the security checks read.
    Evidence this pack doesn't collect (public RDS snapshots, account-level
    S3 Block Public Access) is left out, so those checks report NO DATA
    rather than a false PASS."""
    regions = {}
    for region, rd in evidence["Regions"].items():
        regions[region] = {
            "Security": rd.get("Security") or {},
            "WideOpenSecurityGroups": (rd.get("Network") or {}).get("WideOpenSecurityGroupRules"),
            "DefaultSecurityGroupsWithRules": vpc.default_security_groups_with_rules(
                (rd.get("Network") or {}).get("SecurityGroups") or []
            ),
            "Compute": rd.get("Compute") or {},
            "RdsExposure": data_stores.rds_exposure((rd.get("DataStores") or {}).get("RdsInstances") or []),
        }
    sec = evidence["Global"].get("Security") or {}
    bundle_global = {"IamFindings": sec.get("IamFindings"), "DataStores": evidence["Global"].get("DataStores")}
    if evidence["Global"].get("CloudTrail") is not None:
        bundle_global["CloudTrail"] = evidence["Global"]["CloudTrail"]
    return {"Regions": regions, "Global": bundle_global, access.KEY: access.denied(evidence)}


def _security_check_section(evidence: dict) -> str:
    results = security_checks.evaluate_checks(security_bundle(evidence))
    ordered = sorted(
        results,
        key=lambda r: (
            r.check.question or "SEC99",
            {engine.FAIL: 0, engine.NO_DATA: 1, engine.PASS: 2}[r.status],
            engine.SEVERITY_RANK[r.check.severity],
        ),
    )
    rows = [
        {
            "Question": r.check.question or "--",
            "Status": r.status,
            "Severity": r.check.severity,
            "Check": r.check.title,
            "Control": r.check.reference,
            "Affected": engine.scope_text(r.affected) if r.failed else "--",
        }
        for r in ordered
    ]
    return (
        "The security review's deterministic checks run against this evidence pack, ordered by "
        "the Security pillar question each one informs. A FAIL is evidence against that "
        "question's best practices, not a rating of it; NO DATA marks evidence this pack doesn't "
        "collect (run `aws-security-review` for those) or a call the run was denied.\n\n"
        + findings_table(rows, ["Question", "Status", "Severity", "Check", "Control", "Affected"])
        + "".join(f"\n\n_{escape_text(r.check.title)}: {escape_text(r.note)}_" for r in ordered if r.note)
    )


def _add_kpis(report: Report, evidence: dict, pillars: list[str]) -> None:
    regions = evidence["Regions"]
    report.add_kpi("Regions", len(regions), ", ".join(list(regions)[:3]) + ("..." if len(regions) > 3 else ""))
    report.add_kpi("Pillars", len(pillars), "with evidence in this pack")
    if "security" in pillars:
        results = security_checks.evaluate_checks(security_bundle(evidence))
        failed = [r for r in results if r.failed]
        severe = sum(1 for r in failed if r.check.severity in ("CRITICAL", "HIGH"))
        evaluated = sum(1 for r in results if r.status != engine.NO_DATA)
        report.add_kpi(
            "Security checks failed",
            f"{len(failed)}/{evaluated}",
            f"{severe} critical or high",
            "bad" if severe else ("warn" if failed else "good"),
        )
    silent = sum(len(r["Observability"]["AlarmsWithNoActions"]) for r in regions.values())
    alarms = sum(len(r["Observability"]["Alarms"]) for r in regions.values())
    report.add_kpi("Alarms without actions", silent, f"of {alarms} CloudWatch alarms", "warn" if silent else "neutral")
    plans = sum(len(r["Backup"]["BackupPlans"]) for r in regions.values())
    report.add_kpi("Backup plans", plans, "AWS Backup", "neutral" if plans else "warn")
    budgets = evidence["Global"]["Cost"].get("Budgets") or []
    report.add_kpi("Budgets", len(budgets), "AWS Budgets", "neutral" if budgets else "warn")


def build_report(evidence: dict, pillars: list[str]) -> Report:
    report = Report(
        title="AWS Well-Architected Review -- Evidence Pack",
        subtitle=f"Pillars: {', '.join(pillars)}",
        intro=(
            "This is collected evidence for a Well-Architected review, not "
            "the review itself: raw counts and resource lists organized by "
            "pillar, with no verdicts attached. Start with the pillar "
            "section you are reviewing; the next section explains how the "
            "evidence maps to the framework's questions."
        ),
    )
    report.add_section(
        "How to use this evidence pack",
        "This report is collected evidence only. Read the matching "
        "`references/pillars/<pillar>.md` question catalogue alongside each "
        "section below and rate each best-practice question "
        "Yes / Partial / No / Not applicable based on the evidence, citing "
        "the specific resource IDs found here.",
    )

    _add_kpis(report, evidence, pillars)
    access.add_section(report, evidence)

    for pillar in pillars:
        body = []
        for region, region_data in evidence["Regions"].items():
            body.append(f"\n**Region {region}:**\n")
            body.extend(PILLAR_EVIDENCE_SUMMARY[pillar](evidence, region_data))
        report.add_section(pillar.replace("-", " ").title(), "\n".join(body))
        if pillar == "security":
            report.add_section("Security Baseline Checks", _security_check_section(evidence), level=3)

    iam_findings = evidence["Global"]["Security"]["IamFindings"]
    report.add_section(
        "Account-wide IAM Evidence (Security + Operational Excellence)",
        findings_table(
            [
                {"Signal": "Console users without MFA", "Count": len(iam_findings["ConsoleUsersWithoutMfa"])},
                {"Signal": "Access keys to review", "Count": len(iam_findings["AccessKeysToReview"])},
                {"Signal": "Root account risks", "Count": len(iam_findings["RootAccountRisks"])},
                {"Signal": "Password policy set", "Count": iam_findings["PasswordPolicySet"]},
            ],
            ["Signal", "Count"],
        ),
    )

    ct = evidence["Global"].get("CloudTrail", {})
    if ct:
        report.add_section(
            "Account-wide CloudTrail Evidence (Security SEC01/SEC04, Operational Excellence OPS04)",
            "\n".join(
                [
                    f"- Multi-region trail configured: {ct.get('HasMultiRegionTrail')}",
                    f"- A trail is actively logging: {ct.get('HasLoggingTrail')}",
                    f"- A multi-region trail is logging: {ct.get('HasLoggingMultiRegionTrail')}",
                    f"- Log file validation enabled: {ct.get('HasLogFileValidation')}",
                ]
            ),
        )

    budgets = evidence["Global"]["Cost"].get("Budgets") or []
    report.add_section(
        "Account-wide Budgets Evidence (Cost Optimization COST01/COST03)",
        f"{len(budgets)} AWS Budget(s) configured."
        if budgets
        else "No AWS Budgets configured -- COST01/COST03 evidence gap.",
    )

    if "Workload" in evidence:
        workload = evidence["Workload"]["Workload"]
        improvements = evidence["Workload"]["ImprovementsByPillar"]
        # WorkloadName is free text set by whoever created the workload --
        # escape it, since this lands in a section body (which Report does
        # not escape, by contract) and then in browser-opened HTML.
        lines = [
            f"Cross-referenced against WA Tool workload "
            f"**{escape_text(workload.get('WorkloadName', '?'))}** "
            f"({escape_text(workload.get('WorkloadId', '?'))})."
        ]
        for pillar_id, items in improvements.items():
            if items:
                lines.append(f"- {pillar_id}: {len(items)} outstanding improvement item(s) already recorded in the WA Tool")
        report.add_section("Well-Architected Tool Cross-Reference", "\n".join(lines))

    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    regions = resolve_regions(ctx, args)
    pillars = list(PILLARS) if args.pillar == "all" else [args.pillar]

    evidence = collect(ctx, regions, args.workload_id)

    if args.json_out:
        jsonutil.write(evidence, args.json_out)
        print(f"Raw evidence JSON written to {args.json_out}")

    report = build_report(evidence, pillars)
    paths = report.save(args.output_dir, "well-architected-evidence", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
