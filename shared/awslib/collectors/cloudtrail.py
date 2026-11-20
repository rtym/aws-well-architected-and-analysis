"""CloudTrail posture: is there a multi-region trail, is it logging, does it
have log file validation enabled. Answers Security SEC01/SEC04 and
Operational Excellence OPS04 evidence gaps left open in the WA pillar refs.
"""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..session import PERMISSION_DENIED_CODES, AwsContext, ignore_access_denied

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

    A trail whose status the scan was denied gets `_StatusNotRead`, and the
    denial is recorded against that trail: its missing status used to read
    as "not logging" and fail CloudTrail.1 with nothing in Access Gaps.
    """
    ct = ctx.client("cloudtrail", region=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    for trail in trails:
        ref = trail.get("TrailARN") or trail["Name"]
        status = _trail_call(ctx, region, ref, lambda ref=ref: ct.get_trail_status(Name=ref), None)
        if status is _NOT_READ:
            trail["_StatusNotRead"] = True
            status = None
        trail["_Status"] = status
        selectors = _trail_call(
            ctx, region, ref, lambda ref=ref: ct.get_event_selectors(TrailName=ref).get("EventSelectors", []), []
        )
        trail["_EventSelectors"] = [] if selectors is _NOT_READ else selectors
    return trails


# What `_trail_call` returns for a read the scan was denied.
_NOT_READ = object()


def _trail_call(ctx: AwsContext, region: str, trail_ref: str, call, unresolvable):
    """One per-trail read. A trail this account can list but not resolve
    gets `unresolvable`; a denied read is recorded against the trail and
    returns `_NOT_READ`; anything else raises."""
    try:
        return call()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in _UNRESOLVABLE_TRAIL_CODES:
            return unresolvable
        if code in PERMISSION_DENIED_CODES:
            ctx.record_denied("describe_trails", region, code, exc.operation_name, trail_ref)
            return _NOT_READ
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
        # Trails whose status the scan was denied: "not logging" above may
        # be "not known" for these.
        "TrailStatusNotRead": [t.get("TrailARN") or t.get("Name") for t in trails if t.get("_StatusNotRead")],
    }
