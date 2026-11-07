"""CloudTrail posture: is there a multi-region trail, is it logging, does it
have log file validation enabled. Answers Security SEC01/SEC04 and
Operational Excellence OPS04 evidence gaps left open in the WA pillar refs.
"""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..session import AwsContext, ignore_access_denied

# A trail listed by DescribeTrails but not resolvable from this account or
# region -- record it with unknown status rather than abort the scan.
_UNRESOLVABLE_TRAIL_CODES = {"TrailNotFoundException", "CloudTrailARNInvalidException"}


@ignore_access_denied(default=list)
def describe_trails(ctx: AwsContext, region: str) -> list[dict]:
    """Every trail visible from `region`, with status and event selectors.

    Status and selectors are fetched by trail ARN, not name: AWS requires
    the ARN for a shadow trail (a multi-region trail seen from a region
    other than its home region) and for an organization trail seen from a
    member account. By name, those calls raise TrailNotFoundException --
    which crashed every scan run from a region other than the trail's home.
    """
    ct = ctx.client("cloudtrail", region=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    for trail in trails:
        ref = trail.get("TrailARN") or trail["Name"]
        trail["_Status"] = _trail_status(ct, ref)
        trail["_EventSelectors"] = _event_selectors(ct, ref)
    return trails


@ignore_access_denied(default=lambda: None)
def _trail_status(ct, trail_ref: str) -> dict | None:
    try:
        return ct.get_trail_status(Name=trail_ref)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in _UNRESOLVABLE_TRAIL_CODES:
            return None
        raise


@ignore_access_denied(default=list)
def _event_selectors(ct, trail_ref: str) -> list[dict]:
    try:
        return ct.get_event_selectors(TrailName=trail_ref).get("EventSelectors", [])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in _UNRESOLVABLE_TRAIL_CODES:
            return []
        raise


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
        # The control that matters (CIS / FSBP CloudTrail.1) is one trail
        # that is both multi-region AND logging; the two flags above can
        # each be true while no single trail satisfies both.
        "HasLoggingMultiRegionTrail": any(t in logging_trails for t in multi_region),
        "HasLogFileValidation": bool(validated_trails),
    }
