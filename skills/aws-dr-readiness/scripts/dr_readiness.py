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

from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions  # noqa: E402
from shared.awslib.collectors import backup, data_stores, dr  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402


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


def build_report(data: dict) -> Report:
    report = Report(
        title="AWS Disaster Recovery Readiness",
        subtitle="AWS Backup, RDS/S3 replication, and Route 53 failover posture",
    )

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
    if rds["SingleAzInstances"] or rds["InstancesWithReadReplicas"] or rds["CrossRegionOrGlobalClusters"]:
        chart_uri = charts.bar_chart(
            ["Single-AZ", "With read replicas", "Cross-region/global clusters"],
            [len(rds["SingleAzInstances"]), len(rds["InstancesWithReadReplicas"]), len(rds["CrossRegionOrGlobalClusters"])],
            title="RDS DR posture",
            ylabel="Count",
        )
        report.add_section("RDS Disaster Recovery Signals", f"![RDS DR posture]({chart_uri})")
        if rds["SingleAzInstances"]:
            rows = [{"DB instance": i.get("DBInstanceIdentifier")} for i in rds["SingleAzInstances"]]
            report.add_section("RDS Instances Without Multi-AZ", findings_table(rows, ["DB instance"]))
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
