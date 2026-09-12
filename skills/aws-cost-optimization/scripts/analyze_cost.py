#!/usr/bin/env python3
"""Analyze AWS cost & usage trends, Reserved Instance / Savings Plans
coverage and utilization, rightsizing opportunities, and idle-resource waste
(unattached EBS, unassociated EIPs, stopped instances) -- then render a
Markdown/HTML/PDF cost-optimization report with trend and coverage charts.

Read-only. Cost Explorer, Compute Optimizer, and Trusted Advisor calls are
all Describe/Get operations; nothing here purchases or modifies anything.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from shared.awslib.cli import base_parser, formats_tuple, make_context  # noqa: E402
from shared.awslib.collectors import compute, cost  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Analyze AWS cost, RI/Savings Plans posture, and rightsizing opportunities.")
    parser.add_argument("--lookback-days", type=int, default=90, help="Cost & usage lookback window in days (default: 90)")
    parser.add_argument(
        "--compute-optimizer-regions",
        default=None,
        help="Comma-separated regions to also query Compute Optimizer in (default: --region only)",
    )
    return parser.parse_args(argv)


def date_range(lookback_days: int) -> tuple[str, str]:
    """Cost Explorer interprets TimePeriod dates in UTC, so the window must
    be built from the UTC date -- `date.today()` returns the *local* date,
    which silently shifts the window by a day for anyone running this far
    enough east or west of UTC."""
    end = datetime.datetime.now(datetime.timezone.utc).date()
    start = end - datetime.timedelta(days=lookback_days)
    return start.isoformat(), end.isoformat()


def collect(ctx, start: str, end: str, co_regions: list[str]) -> dict:
    data = {"CostReport": cost.collect_cost_report(ctx, start, end)}
    data["ComputeOptimizerEc2"] = {
        region: cost.compute_optimizer_ec2_recommendations(ctx, region) for region in co_regions
    }
    data["ComputeOptimizerEbs"] = {
        region: cost.compute_optimizer_ebs_recommendations(ctx, region) for region in co_regions
    }
    data["IdleResources"] = {
        region: {
            "UnattachedVolumes": compute.unattached_volumes(compute.describe_volumes(ctx, region)),
            "UnassociatedEips": compute.unassociated_eips(compute.describe_addresses(ctx, region)),
            "StoppedInstances": compute.idle_instance_candidates(compute.describe_instances(ctx, region)),
        }
        for region in co_regions
    }
    return data


def monthly_cost_series(cost_by_service: list[dict]) -> tuple[list[str], dict[str, list[float]]]:
    months = [period["TimePeriod"]["Start"] for period in cost_by_service]
    service_totals: dict[str, float] = {}
    per_month_by_service: dict[str, dict[str, float]] = {}
    for period in cost_by_service:
        month = period["TimePeriod"]["Start"]
        per_month_by_service[month] = {}
        for group in period.get("Groups", []):
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            service_totals[service] = service_totals.get(service, 0.0) + amount
            per_month_by_service[month][service] = amount
    top_services = sorted(service_totals, key=service_totals.get, reverse=True)[:8]
    series = {svc: [per_month_by_service.get(m, {}).get(svc, 0.0) for m in months] for svc in top_services}
    return months, series


def build_report(data: dict, start: str, end: str) -> Report:
    report = Report(
        title="AWS Cost Optimization Report",
        subtitle=f"Cost & usage window: {start} to {end}",
        meta={},
    )

    cr = data["CostReport"]
    months, series = monthly_cost_series(cr["CostByService"])
    if months and series:
        trend_uri = charts.line_chart(months, series, title="Monthly cost by top services", ylabel="USD")
        report.add_section("Cost Trend", f"![Cost trend]({trend_uri})")

        total_by_service = {svc: sum(v) for svc, v in series.items()}
        pie_uri = charts.pie_chart(list(total_by_service), list(total_by_service.values()), title="Cost share (top services)")
        report.add_section("Cost Distribution", f"![Cost distribution]({pie_uri})")

    ri_util = cr.get("ReservationUtilization") or {}
    sp_util = cr.get("SavingsPlansUtilization") or {}
    coverage_lines = []
    if ri_util.get("Total"):
        t = ri_util["Total"]
        coverage_lines.append(
            f"- **RI utilization:** {t.get('UtilizationPercentage', 'n/a')}% "
            f"(unused hours cost ~${t.get('UnusedHours', 'n/a')})"
        )
    if sp_util.get("Total"):
        t = sp_util["Total"]["SavingsPlansUtilization"] if "SavingsPlansUtilization" in sp_util.get("Total", {}) else sp_util["Total"]
        coverage_lines.append(f"- **Savings Plans utilization:** {t}")
    if not coverage_lines:
        coverage_lines.append("- No Reserved Instance or Savings Plans utilization data returned (none purchased, or Cost Explorer access not granted).")
    report.add_section("Reservation & Savings Plans Coverage", "\n".join(coverage_lines))

    rightsizing = cr.get("RightsizingRecommendations") or []
    if rightsizing:
        rows = [
            {
                "Resource": r.get("CurrentInstance", {}).get("ResourceId", "?"),
                "Action": r.get("RightsizingType", "?"),
                "Finding": r.get("FindingReasonCodes", []),
            }
            for r in rightsizing[:25]
        ]
        report.add_section(
            "Rightsizing Recommendations (Cost Explorer)",
            findings_table(rows, ["Resource", "Action", "Finding"]),
        )
    else:
        report.add_section("Rightsizing Recommendations (Cost Explorer)", "No rightsizing recommendations returned.")

    co_ec2 = {region: recs for region, recs in data["ComputeOptimizerEc2"].items() if recs}
    if co_ec2:
        rows = []
        for region, recs in co_ec2.items():
            for rec in recs:
                rows.append(
                    {
                        "Region": region,
                        "Instance": rec.get("instanceArn", "?").split("/")[-1],
                        "Finding": rec.get("finding", "?"),
                        "Recommended": ", ".join(
                            opt.get("instanceType", "?") for opt in rec.get("recommendationOptions", [])[:1]
                        ),
                    }
                )
        report.add_section(
            "Compute Optimizer -- EC2 Recommendations", findings_table(rows, ["Region", "Instance", "Finding", "Recommended"])
        )

    idle_rows = []
    for region, idle in data["IdleResources"].items():
        idle_rows.append(
            {
                "Region": region,
                "Unattached EBS": len(idle["UnattachedVolumes"]),
                "Unassociated EIPs": len(idle["UnassociatedEips"]),
                "Stopped Instances": len(idle["StoppedInstances"]),
            }
        )
    if idle_rows:
        report.add_section(
            "Idle / Waste Candidates",
            findings_table(idle_rows, ["Region", "Unattached EBS", "Unassociated EIPs", "Stopped Instances"]),
        )
        counts_by_region = {r["Region"]: r["Unattached EBS"] + r["Unassociated EIPs"] + r["Stopped Instances"] for r in idle_rows}
        if any(counts_by_region.values()):
            waste_uri = charts.bar_chart(list(counts_by_region), list(counts_by_region.values()), title="Idle resource candidates by region", ylabel="Count")
            report.add_section("Idle Resource Chart", f"![Idle resources]({waste_uri})")

    ta_checks = cr.get("TrustedAdvisorCostChecks") or []
    if ta_checks:
        rows = [{"Check": c["check"], "Status": c["status"], "Flagged": len(c.get("flaggedResources", []))} for c in ta_checks]
        report.add_section("Trusted Advisor Cost Checks", findings_table(rows, ["Check", "Status", "Flagged"]))

    anomalies = cr.get("Anomalies") or []
    if anomalies:
        rows = [
            {
                "Account": a.get("AccountId", "?"),
                "Impact ($)": a.get("Impact", {}).get("TotalImpact", "?"),
                "Started": a.get("AnomalyStartDate", "?"),
            }
            for a in anomalies[:20]
        ]
        report.add_section("Cost Anomalies", findings_table(rows, ["Account", "Impact ($)", "Started"]))

    budgets = cr.get("Budgets") or []
    if budgets:
        rows = [
            {
                "Budget": b.get("BudgetName", "?"),
                "Limit": f"{b.get('BudgetLimit', {}).get('Amount', '?')} {b.get('BudgetLimit', {}).get('Unit', '')}".strip(),
                "Actual spend": f"{b.get('CalculatedSpend', {}).get('ActualSpend', {}).get('Amount', '?')}",
                "Type": b.get("BudgetType", "?"),
            }
            for b in budgets
        ]
        report.add_section("AWS Budgets Configured", findings_table(rows, ["Budget", "Limit", "Actual spend", "Type"]))
    else:
        report.add_section(
            "AWS Budgets Configured",
            "No AWS Budgets configured -- consider setting at least one cost budget with an alert threshold for proactive spend governance.",
        )

    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    start, end = date_range(args.lookback_days)
    co_regions = (
        [r.strip() for r in args.compute_optimizer_regions.split(",") if r.strip()]
        if args.compute_optimizer_regions
        else [ctx.region or "us-east-1"]
    )

    data = collect(ctx, start, end, co_regions)

    if args.json_out:
        jsonutil.write(data, args.json_out)
        print(f"Raw cost evidence JSON written to {args.json_out}")

    report = build_report(data, start, end)
    paths = report.save(args.output_dir, "cost-optimization", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
