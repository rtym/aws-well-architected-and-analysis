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


def service_totals(cost_by_service: list[dict]) -> dict[str, float]:
    """Total spend per service over the whole window, every service."""
    totals: dict[str, float] = {}
    for period in cost_by_service:
        for group in period.get("Groups", []):
            service = group["Keys"][0]
            totals[service] = totals.get(service, 0.0) + float(group["Metrics"]["UnblendedCost"]["Amount"])
    return totals


def complete_months(cost_by_service: list[dict]) -> list[tuple[str, float]]:
    """(month start, total) for periods covering a whole calendar month.
    The first and last periods of a lookback window are usually partial,
    and comparing a partial month with a full one overstates the change."""
    months = []
    for period in cost_by_service:
        start, end = period["TimePeriod"]["Start"], period["TimePeriod"]["End"]
        if start.endswith("-01") and end.endswith("-01") and end > start:
            total = sum(float(g["Metrics"]["UnblendedCost"]["Amount"]) for g in period.get("Groups", []))
            months.append((start[:7], total))
    return months


def rightsizing_monthly_savings(rec: dict) -> float:
    """Estimated monthly savings of one Cost Explorer rightsizing
    recommendation: the terminate estimate, or the default (else first)
    modify target's estimate."""
    def _amount(value) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    if rec.get("RightsizingType") == "TERMINATE":
        return _amount((rec.get("TerminateRecommendationDetail") or {}).get("EstimatedMonthlySavings"))
    targets = (rec.get("ModifyRecommendationDetail") or {}).get("TargetInstances") or []
    if not targets:
        return 0.0
    chosen = next((t for t in targets if t.get("DefaultTargetInstance")), targets[0])
    return _amount(chosen.get("EstimatedMonthlySavings"))


def _usd(value: float) -> str:
    return charts.format_value(value, "usd")


def _add_kpis(report: Report, data: dict) -> None:
    cr = data["CostReport"]
    totals = service_totals(cr["CostByService"])
    report.add_kpi("Spend in window", _usd(sum(totals.values())), f"{len(totals)} services")
    months = complete_months(cr["CostByService"])
    if len(months) >= 2:
        (prev_m, prev), (last_m, last) = months[-2], months[-1]
        change = f"{100 * (last - prev) / prev:+.0f}%" if prev else "n/a"
        report.add_kpi("Last full month", _usd(last), f"{last_m}: {change} vs {prev_m}")
    elif months:
        report.add_kpi("Last full month", _usd(months[-1][1]), months[-1][0])
    savings = sum(rightsizing_monthly_savings(r) for r in cr.get("RightsizingRecommendations") or [])
    report.add_kpi(
        "Rightsizing savings",
        f"{_usd(savings)}/mo",
        f"{len(cr.get('RightsizingRecommendations') or [])} recommendation(s)",
        "warn" if savings else "good",
    )
    ri = ((cr.get("ReservationUtilization") or {}).get("Total") or {}).get("UtilizationPercentage")
    sp = (((cr.get("SavingsPlansUtilization") or {}).get("Total") or {}).get("Utilization") or {}).get("UtilizationPercentage")
    for label, value in (("RI utilization", ri), ("Savings Plans utilization", sp)):
        if value is None:
            continue
        pct = float(value)
        report.add_kpi(label, f"{pct:.0f}%", "of purchased commitment used", "good" if pct >= 90 else "warn" if pct >= 70 else "bad")
    idle = sum(
        len(i["UnattachedVolumes"]) + len(i["UnassociatedEips"]) + len(i["StoppedInstances"])
        for i in data["IdleResources"].values()
    )
    report.add_kpi("Idle resources", idle, "unattached volumes, unused EIPs, stopped instances", "warn" if idle else "good")
    budgets = cr.get("Budgets") or []
    report.add_kpi("Budgets", len(budgets), "configured" if budgets else "none: no spend alerting", "good" if budgets else "bad")


def build_report(data: dict, start: str, end: str) -> Report:
    report = Report(
        title="AWS Cost Optimization Report",
        subtitle=f"Cost & usage window: {start} to {end}",
        meta={},
        intro=(
            f"This report covers this account's spend from {start} to {end}: "
            "the cost trend by service, Reserved Instance and Savings Plans "
            "posture, rightsizing recommendations, and idle resources that "
            "cost money without doing work. Start with the Cost Trend chart "
            "for the overall shape, then the Idle / Waste Candidates and "
            "Rightsizing sections for the items with a concrete saving "
            "attached."
        ),
    )

    _add_kpis(report, data)
    cr = data["CostReport"]
    months, series = monthly_cost_series(cr["CostByService"])
    if months and series:
        # Stacked columns show the total trend and its make-up at once; the
        # five largest services keep their own color, the rest fold into
        # Other so no color is reused.
        top = list(series)[:5]
        all_by_month = [
            sum(float(g["Metrics"]["UnblendedCost"]["Amount"]) for g in period.get("Groups", []))
            for period in cr["CostByService"]
        ]
        stacked = {svc: series[svc] for svc in top}
        other = [max(total - sum(series[svc][i] for svc in top), 0.0) for i, total in enumerate(all_by_month)]
        if any(v > 0.005 for v in other):
            stacked["Other"] = other
        colors = {svc: charts.PALETTE[i] for i, svc in enumerate(top)}
        colors["Other"] = charts.OTHER_COLOR
        labels = [m[:7] for m in months]
        trend_uri = charts.stacked_bar_chart(
            labels, stacked, title="Monthly cost by service", value_format="usd", colors=colors
        )
        report.add_section(
            "Cost Trend",
            f"![Cost trend]({trend_uri})\n\n"
            "The first and last columns may cover part of a month, depending on where the window starts and ends.",
        )

        totals = service_totals(cr["CostByService"])
        pie_uri = charts.donut_chart(list(totals), list(totals.values()), title="Cost share by service", value_format="usd")
        ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:10]
        grand = sum(totals.values()) or 1.0
        top_rows = [{"Service": svc, "Spend": _usd(v), "Share": f"{100 * v / grand:.1f}%"} for svc, v in ranked]
        report.add_section(
            "Cost Distribution",
            f"![Cost distribution]({pie_uri})\n\n" + findings_table(top_rows, ["Service", "Spend", "Share"]),
        )

    ri_util = cr.get("ReservationUtilization") or {}
    sp_util = cr.get("SavingsPlansUtilization") or {}
    coverage_lines = []
    if ri_util.get("Total"):
        # GetReservationUtilization Total: UtilizationPercentage and
        # UnusedHours are strings; UnusedHours is a count of hours, not a
        # dollar amount -- the dollar figure is NetRISavings.
        t = ri_util["Total"]
        line = f"- **Reserved Instance utilization:** {t.get('UtilizationPercentage', 'n/a')}%"
        if t.get("UnusedHours"):
            line += f", {t['UnusedHours']} purchased hours unused"
        if t.get("NetRISavings"):
            line += f", net savings ${t['NetRISavings']} over the window"
        coverage_lines.append(line)
    if sp_util.get("Total"):
        # GetSavingsPlansUtilization Total nests the numbers one level
        # down: Total.Utilization.{UtilizationPercentage, UnusedCommitment}
        # and Total.Savings.NetSavings.
        util = sp_util["Total"].get("Utilization", {})
        savings = sp_util["Total"].get("Savings", {})
        line = f"- **Savings Plans utilization:** {util.get('UtilizationPercentage', 'n/a')}%"
        if util.get("UnusedCommitment"):
            line += f", ${util['UnusedCommitment']} committed but unused"
        if savings.get("NetSavings"):
            line += f", net savings ${savings['NetSavings']} over the window"
        coverage_lines.append(line)
    if not coverage_lines:
        coverage_lines.append("- No Reserved Instance or Savings Plans utilization data returned (none purchased, or Cost Explorer access not granted).")
    report.add_section("Reservation & Savings Plans Coverage", "\n".join(coverage_lines))

    rightsizing = cr.get("RightsizingRecommendations") or []
    if rightsizing:
        ranked = sorted(rightsizing, key=rightsizing_monthly_savings, reverse=True)
        rows = [
            {
                "Resource": r.get("CurrentInstance", {}).get("ResourceId", "?"),
                "Action": r.get("RightsizingType", "?"),
                "Est. monthly savings": _usd(rightsizing_monthly_savings(r)),
                "Finding": r.get("FindingReasonCodes", []),
            }
            for r in ranked[:25]
        ]
        report.add_section(
            "Rightsizing Recommendations (Cost Explorer)",
            "Largest estimated saving first. Estimates come from Cost Explorer and assume the "
            "recommended change is made for a full month.\n\n"
            + findings_table(rows, ["Resource", "Action", "Est. monthly savings", "Finding"]),
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
            waste_uri = charts.bar_chart(list(counts_by_region), list(counts_by_region.values()), title="Idle resource candidates by region", horizontal=True)
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
