"""CloudTrail posture: is there a multi-region trail, is it logging, does it
have log file validation enabled. Answers Security SEC01/SEC04 and
Operational Excellence OPS04 evidence gaps left open in the WA pillar refs.
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied


@ignore_access_denied(default=list)
def describe_trails(ctx: AwsContext, region: str) -> list[dict]:
    ct = ctx.client("cloudtrail", region=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    for trail in trails:
        trail["_Status"] = _trail_status(ct, trail["Name"])
        trail["_EventSelectors"] = _event_selectors(ct, trail["Name"])
    return trails


@ignore_access_denied(default=lambda: None)
def _trail_status(ct, name: str) -> dict:
    return ct.get_trail_status(Name=name)


@ignore_access_denied(default=list)
def _event_selectors(ct, trail_name: str) -> list[dict]:
    return ct.get_event_selectors(TrailName=trail_name).get("EventSelectors", [])


def cloudtrail_posture(ctx: AwsContext, home_region: str) -> dict:
    """CloudTrail trails are visible account-wide from any single region call
    (multi-region trails included) -- one call from the home region is
    enough; no need to repeat this per region scanned."""
    trails = describe_trails(ctx, home_region)
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    logging_trails = [t for t in trails if (t.get("_Status") or {}).get("IsLogging")]
    validated_trails = [t for t in trails if t.get("LogFileValidationEnabled")]
    return {
        "Trails": trails,
        "HasMultiRegionTrail": bool(multi_region),
        "HasLoggingTrail": bool(logging_trails),
        "HasLogFileValidation": bool(validated_trails),
    }
