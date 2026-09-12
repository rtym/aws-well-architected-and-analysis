"""CloudWatch alarms and dashboards -- OPS08/OPS09/REL06 evidence: does the
account actually have monitoring configured, not just resources deployed.
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


@ignore_access_denied(default=list)
def describe_alarms(ctx: AwsContext, region: str) -> list[dict]:
    cw = ctx.client("cloudwatch", region=region)
    return list(paginate(cw, "describe_alarms", "MetricAlarms"))


@ignore_access_denied(default=list)
def list_dashboards(ctx: AwsContext, region: str) -> list[dict]:
    cw = ctx.client("cloudwatch", region=region)
    return list(paginate(cw, "list_dashboards", "DashboardEntries"))


def alarms_in_alarm_state(alarms: list[dict]) -> list[dict]:
    return [a for a in alarms if a.get("StateValue") == "ALARM"]


def alarms_with_no_actions(alarms: list[dict]) -> list[dict]:
    """An alarm with no AlarmActions/OKActions/InsufficientDataActions is
    effectively decorative -- it can fire and nobody/nothing is notified."""
    return [
        a
        for a in alarms
        if not (a.get("AlarmActions") or a.get("OKActions") or a.get("InsufficientDataActions"))
    ]


def collect_region_observability(ctx: AwsContext, region: str) -> dict:
    alarms = describe_alarms(ctx, region)
    return {
        "Region": region,
        "Alarms": alarms,
        "Dashboards": list_dashboards(ctx, region),
        "AlarmsInAlarmState": alarms_in_alarm_state(alarms),
        "AlarmsWithNoActions": alarms_with_no_actions(alarms),
    }
