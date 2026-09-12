"""Cost Explorer, Savings Plans / Reserved Instance utilization & coverage,
rightsizing (Compute Optimizer + CE), and Trusted Advisor cost checks.

Cost Explorer is a single global endpoint billed per API call -- collectors
here are intentionally coarse-grained (a handful of calls) rather than
looping per resource.
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


def cost_and_usage_by_service(
    ctx: AwsContext, start: str, end: str, granularity: str = "MONTHLY"
) -> list[dict]:
    ce = ctx.client("ce", region="us-east-1")
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity=granularity,
        Metrics=["UnblendedCost", "UsageQuantity"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    return resp["ResultsByTime"]


def cost_by_linked_account(ctx: AwsContext, start: str, end: str) -> list[dict]:
    ce = ctx.client("ce", region="us-east-1")
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
    )
    return resp["ResultsByTime"]


@ignore_access_denied(default=dict)
def cost_forecast(ctx: AwsContext, start: str, end: str) -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_cost_forecast(
        TimePeriod={"Start": start, "End": end}, Metric="UNBLENDED_COST", Granularity="MONTHLY"
    )


@ignore_access_denied(default=dict)
def reservation_utilization(ctx: AwsContext, start: str, end: str) -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_reservation_utilization(TimePeriod={"Start": start, "End": end})


@ignore_access_denied(default=dict)
def reservation_coverage(ctx: AwsContext, start: str, end: str) -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_reservation_coverage(TimePeriod={"Start": start, "End": end})


@ignore_access_denied(default=dict)
def savings_plans_utilization(ctx: AwsContext, start: str, end: str) -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_savings_plans_utilization(TimePeriod={"Start": start, "End": end})


@ignore_access_denied(default=dict)
def savings_plans_coverage(ctx: AwsContext, start: str, end: str) -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_savings_plans_coverage(TimePeriod={"Start": start, "End": end})


@ignore_access_denied(default=list)
def rightsizing_recommendations(ctx: AwsContext, service: str = "AmazonEC2") -> list[dict]:
    ce = ctx.client("ce", region="us-east-1")
    resp = ce.get_rightsizing_recommendation(Service=service)
    return resp.get("RightsizingRecommendations", [])


@ignore_access_denied(default=dict)
def savings_plans_purchase_recommendation(
    ctx: AwsContext, term_years: str = "ONE_YEAR", payment_option: str = "NO_UPFRONT"
) -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_savings_plans_purchase_recommendation(
        SavingsPlansType="COMPUTE_SP",
        TermInYears=term_years,
        PaymentOption=payment_option,
        LookbackPeriodInDays="THIRTY_DAYS",
    )


@ignore_access_denied(default=dict)
def reserved_instance_purchase_recommendation(ctx: AwsContext, service: str = "Amazon Elastic Compute Cloud - Compute") -> dict:
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_reservation_purchase_recommendation(Service=service)


@ignore_access_denied(default=list)
def anomalies(ctx: AwsContext, start: str, end: str) -> list[dict]:
    """Cost Anomaly Detection results, if a monitor is configured."""
    ce = ctx.client("ce", region="us-east-1")
    return ce.get_anomalies(DateInterval={"StartDate": start, "EndDate": end}).get(
        "Anomalies", []
    )


@ignore_access_denied(default=list)
def compute_optimizer_ec2_recommendations(ctx: AwsContext, region: str) -> list[dict]:
    co = ctx.client("compute-optimizer", region=region)
    return co.get_ec2_instance_recommendations().get("instanceRecommendations", [])


@ignore_access_denied(default=list)
def compute_optimizer_ebs_recommendations(ctx: AwsContext, region: str) -> list[dict]:
    co = ctx.client("compute-optimizer", region=region)
    return co.get_ebs_volume_recommendations().get("volumeRecommendations", [])


@ignore_access_denied(default=list)
def budgets(ctx: AwsContext) -> list[dict]:
    """AWS Budgets -- global service, keyed by account ID, always us-east-1."""
    bg = ctx.client("budgets", region="us-east-1")
    account_id = ctx.account_id()
    return list(paginate(bg, "describe_budgets", "Budgets", AccountId=account_id))


@ignore_access_denied(default=list)
def trusted_advisor_cost_checks(ctx: AwsContext) -> list[dict]:
    """Requires Business/Enterprise Support; Trusted Advisor is us-east-1 only."""
    support = ctx.client("support", region="us-east-1")
    checks = support.describe_trusted_advisor_checks(language="en")["checks"]
    cost_checks = [c for c in checks if c["category"] == "cost_optimizing"]
    results = []
    for check in cost_checks:
        result = support.describe_trusted_advisor_check_result(checkId=check["id"])["result"]
        results.append({"check": check["name"], "status": result["status"], "flaggedResources": result.get("flaggedResources", [])})
    return results


def collect_cost_report(ctx: AwsContext, start: str, end: str) -> dict:
    return {
        "TimePeriod": {"Start": start, "End": end},
        "CostByService": cost_and_usage_by_service(ctx, start, end),
        "CostByAccount": cost_by_linked_account(ctx, start, end),
        "Forecast": cost_forecast(ctx, end, _add_days(end, 30)),
        "ReservationUtilization": reservation_utilization(ctx, start, end),
        "ReservationCoverage": reservation_coverage(ctx, start, end),
        "SavingsPlansUtilization": savings_plans_utilization(ctx, start, end),
        "SavingsPlansCoverage": savings_plans_coverage(ctx, start, end),
        "RightsizingRecommendations": rightsizing_recommendations(ctx),
        "SavingsPlansPurchaseRecommendation": savings_plans_purchase_recommendation(ctx),
        "ReservedInstancePurchaseRecommendation": reserved_instance_purchase_recommendation(ctx),
        "Anomalies": anomalies(ctx, start, end),
        "TrustedAdvisorCostChecks": trusted_advisor_cost_checks(ctx),
        "Budgets": budgets(ctx),
    }


def _add_days(date_str: str, days: int) -> str:
    import datetime

    d = datetime.date.fromisoformat(date_str) + datetime.timedelta(days=days)
    return d.isoformat()
