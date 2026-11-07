#!/usr/bin/env python3
"""Assess disaster-recovery readiness: AWS Backup plan/vault coverage and
cross-region copy, RDS Multi-AZ/read-replica/global-cluster topology, S3
cross-region replication, and Route 53 health checks (DNS failover
readiness) -- then render a Markdown/HTML/PDF report mapped against AWS's
DR strategy tiers (backup & restore / pilot light / warm standby /
multi-site active-active).

Read-only. See `${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from shared.analysis import checks as engine  # noqa: E402
from shared.analysis import dr_checks  # noqa: E402
from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions  # noqa: E402
from shared.awslib.collectors import backup, data_stores, dr  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, ScoreArea, Scorecard, findings_table, tone_for_score  # noqa: E402


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Assess AWS Backup coverage, RDS/S3 replication, and Route 53 failover readiness.")
    parser.add_argument("--regions", default=None, help="Comma-separated regions (default: --region only)")
    parser.add_argument("--all-regions", action="store_true", help="Scan every region enabled for this account")
    return parser.parse_args(argv)


def collect(ctx, regions: list[str]) -> dict:
    data = {"Regions": {}}
    all_rds_instances = []
    all_rds_clusters = []
    for region in regions:
        backup_data = backup.collect_region_backup(ctx, region)
        data_store_data = data_stores.collect_region_data_stores(ctx, region)
        data["Regions"][region] = {"Backup": backup_data, "DataStores": data_store_data}
        all_rds_instances.extend(data_store_data["RdsInstances"])
        all_rds_clusters.extend(data_store_data["RdsClusters"])

    global_data_stores = data_stores.collect_global_data_stores(ctx)
    health_checks = dr.list_health_checks(ctx)
    hosted_zones = dr.list_hosted_zones(ctx)

    data["Global"] = {
        "DataStores": global_data_stores,
        "Route53HealthChecks": health_checks,
        "Route53HostedZones": hosted_zones,
    }
    data["Summary"] = dr.dr_readiness_summary(
        _merge_backup(data["Regions"]),
        all_rds_instances,
        all_rds_clusters,
        global_data_stores["S3Buckets"],
        health_checks,
    )
    return data


def _merge_backup(regions: dict) -> dict:
    merged = {"BackupPlans": [], "BackupVaults": [], "PlansWithCrossRegionCopy": [], "FailedJobsRecent": [], "ProtectedResources": []}
    for region_data in regions.values():
        b = region_data["Backup"]
        for key in merged:
            merged[key].extend(b.get(key, []))
    return merged


def _add_headline(report: Report, data: dict, results: list) -> None:
    overall = engine.score(results)
    by_domain = engine.scores_by_domain(results)
    areas = [
        ScoreArea(d, by_domain[d].score, f"{by_domain[d].passed} of {by_domain[d].evaluated} passed" if by_domain[d].evaluated else "no data")
        for d in dr_checks.DOMAINS
        if d in by_domain
    ]
    detail = f"{overall.passed} of {overall.evaluated} checks passed"
    if overall.no_data:
        detail += f"; {overall.no_data} not applicable or without data"
    report.scorecard = Scorecard(
        label="DR readiness",
        score=overall.score,
        band=engine.band(overall.score),
        detail=detail,
        tone=tone_for_score(overall.score),
        areas=areas,
        method=(
            "Score = passed checks / checks with data. A check passes when the recovery mechanism "
            "exists; whether it meets the business's RTO and RPO is a separate judgment."
        ),
    )
    summary = data["Summary"]
    b = summary["Backup"]
    rds = summary["Rds"]
    instances = dr_checks.rds_instance_count(data)
    single_az = len(rds["SingleAzInstances"]) + len(rds.get("SingleAzClusters", []))
    report.add_kpi("Backup plans", b["PlanCount"], f"{b['PlansWithCrossRegionCopy']} with cross-region copy", "good" if b["PlanCount"] else "bad")
    report.add_kpi("Protected resources", b["ProtectedResourceCount"], "with AWS Backup recovery points", "good" if b["ProtectedResourceCount"] else "bad")
    report.add_kpi("Failed backup jobs", b["RecentFailedJobs"], "recent", "warn" if b["RecentFailedJobs"] else "good")
    report.add_kpi(
        "Single-AZ databases",
        single_az,
        f"of {instances} RDS instance(s)" if instances else "no RDS instances",
        "warn" if single_az else ("good" if instances else "neutral"),
    )
    s3 = summary["S3"]
    buckets = len(s3["ReplicatedBuckets"]) + len(s3["UnreplicatedBuckets"])
    report.add_kpi("S3 replication", f"{len(s3['ReplicatedBuckets'])}/{buckets}", "buckets replicating", "neutral")
    report.add_kpi("Health checks", len(summary["Route53HealthChecks"]), "Route 53", "neutral")


def _checks_body(results: list) -> str:
    ordered = sorted(
        results,
        key=lambda r: ({engine.FAIL: 0, engine.NO_DATA: 1, engine.PASS: 2}[r.status], engine.SEVERITY_RANK[r.check.severity]),
    )
    rows = [
        {
            "Status": r.status,
            "Severity": r.check.severity,
            "Check": r.check.title,
            "WA question": r.check.question or "--",
            "Affected": engine.scope_text(r.affected) if r.failed else "--",
        }
        for r in ordered
    ]
    body = (
        "Each check tests whether a recovery mechanism is configured. NO DATA means the check "
        "doesn't apply (no RDS instances, no hosted zone) or the evidence couldn't be read. "
        "**WA question** is the Reliability question the check informs.\n\n"
        + findings_table(rows, ["Status", "Severity", "Check", "WA question", "Affected"])
    )
    failed = [r for r in ordered if r.failed]
    if failed:
        fixes = [
            {"#": n, "Severity": r.check.severity, "Action": f"{r.check.remediation}\n_{r.check.finding}_", "Effort": r.check.effort}
            for n, r in enumerate(failed, start=1)
        ]
        body += "\n\n**What to fix, in order:**\n\n" + findings_table(fixes, ["#", "Severity", "Action", "Effort"])
    return body


def build_report(data: dict) -> Report:
    report = Report(
        title="AWS Disaster Recovery Readiness",
        subtitle="AWS Backup, RDS/S3 replication, and Route 53 failover posture",
        intro=(
            "This report shows what disaster-recovery machinery this account "
            "actually has configured: AWS Backup coverage, how its RDS "
            "databases would survive an Availability Zone or region failure, "
            "S3 replication, and whether DNS failover is even possible. "
            "Start with the Readiness Checks; read each later section "
            "against the recovery-time objectives the business has stated, "
            "not against the most resilient tier by default."
        ),
    )

    results = dr_checks.evaluate_checks(data)
    _add_headline(report, data, results)
    report.add_section("Readiness Checks", _checks_body(results))

    summary = data["Summary"]
    b = summary["Backup"]
    report.add_section(
        "Backup Coverage Summary",
        "\n".join(
            [
                f"- **Backup plans:** {b['PlanCount']}",
                f"- **Backup vaults:** {b['VaultCount']}",
                f"- **Plans with cross-region copy configured:** {b['PlansWithCrossRegionCopy']}",
                f"- **Protected resources tracked by AWS Backup:** {b['ProtectedResourceCount']}",
                f"- **Recent failed backup jobs:** {b['RecentFailedJobs']}",
            ]
        ),
    )

    rds = summary["Rds"]
    single_az_clusters = rds.get("SingleAzClusters", [])
    if rds["SingleAzInstances"] or single_az_clusters or rds["InstancesWithReadReplicas"] or rds["CrossRegionOrGlobalClusters"]:
        chart_uri = charts.bar_chart(
            ["Single-AZ instances", "Single-AZ clusters", "With read replicas", "Cross-region/global clusters"],
            [
                len(rds["SingleAzInstances"]),
                len(single_az_clusters),
                len(rds["InstancesWithReadReplicas"]),
                len(rds["CrossRegionOrGlobalClusters"]),
            ],
            title="RDS DR posture",
            horizontal=True,
        )
        report.add_section(
            "RDS Disaster Recovery Signals",
            f"![RDS DR posture]({chart_uri})\n\n"
            "Instances that belong to an Aurora or Multi-AZ DB cluster are judged "
            "at the cluster level: a cluster counts as Multi-AZ when its instances "
            "span more than one Availability Zone.",
        )
        if rds["SingleAzInstances"]:
            rows = [{"DB instance": i.get("DBInstanceIdentifier")} for i in rds["SingleAzInstances"]]
            report.add_section("RDS Instances Without Multi-AZ", findings_table(rows, ["DB instance"]))
        if single_az_clusters:
            rows = [{"DB cluster": c.get("DBClusterIdentifier"), "Engine": c.get("Engine")} for c in single_az_clusters]
            report.add_section("RDS Clusters in a Single Availability Zone", findings_table(rows, ["DB cluster", "Engine"]))
    else:
        report.add_section("RDS Disaster Recovery Signals", "No RDS instances found in the scanned region(s).")

    s3 = summary["S3"]
    report.add_section(
        "S3 Cross-Region Replication",
        f"**{len(s3['ReplicatedBuckets'])}** bucket(s) have replication configured; "
        f"**{len(s3['UnreplicatedBuckets'])}** do not (not every bucket needs replication -- "
        f"treat this as a prompt to confirm intent per bucket, not a blanket gap).",
    )

    hosted_zones = data.get("Global", {}).get("Route53HostedZones", [])
    report.add_section(
        "Route 53 Hosted Zones",
        f"**{len(hosted_zones)}** hosted zone(s) found -- context for whether DNS-based "
        f"failover is even architecturally possible today; a health check alone does "
        f"nothing without a hosted zone record set up to fail over using it."
        if hosted_zones
        else "No Route 53 hosted zones found -- DNS is managed outside Route 53, or "
        "not managed as a distinct zone at all; DNS-based failover isn't available "
        "as a DR mechanism without one.",
    )

    health_checks = summary["Route53HealthChecks"]
    if health_checks:
        rows = [
            {
                "Health check ID": h.get("Id"),
                "Type": h.get("HealthCheckConfig", {}).get("Type"),
                "Target": h.get("HealthCheckConfig", {}).get("FullyQualifiedDomainName") or h.get("HealthCheckConfig", {}).get("IPAddress"),
            }
            for h in health_checks
        ]
        report.add_section("Route 53 Health Checks (DNS Failover Readiness)", findings_table(rows, ["Health check ID", "Type", "Target"]))
    else:
        report.add_section(
            "Route 53 Health Checks (DNS Failover Readiness)",
            "No Route 53 health checks configured -- if DNS-based failover is part of the DR "
            "strategy, this is a gap; if failover is handled another way (e.g. Global Accelerator, "
            "an application-level router), note that instead.",
        )

    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    regions = resolve_regions(ctx, args)

    data = collect(ctx, regions)

    if args.json_out:
        jsonutil.write(data, args.json_out)
        print(f"Raw DR-readiness evidence JSON written to {args.json_out}")

    report = build_report(data)
    paths = report.save(args.output_dir, "dr-readiness", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
