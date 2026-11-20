"""Service Quotas -- REL01 evidence. Returns the account's configured quota
values for a curated set of commonly-hit quotas; comparing them against
actual resource counts (from the other collectors' inventory) is left to
the caller since that's a cross-collector judgment, not a single API call.
"""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..session import AwsContext, ignore_access_denied, paginate

# (service_code, quota_code, human label) for quotas that commonly bite
# production accounts -- not exhaustive, just the ones worth checking by
# default. Extend this list if a specific review needs more. Codes and names
# are from the service's quota table in the AWS General Reference (see
# SOURCES.md); a code asked for under the wrong service code returns
# nothing, and the row silently disappears from the evidence.
COMMON_QUOTAS = (
    ("ec2", "L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"),
    ("vpc", "L-F678F1CE", "VPCs per Region"),
    ("vpc", "L-E79EC296", "VPC security groups per Region"),
    ("vpc", "L-0EA8095F", "Inbound or outbound rules per security group"),
    ("vpc", "L-DF5E4CA3", "Network interfaces per Region"),
    ("elasticloadbalancing", "L-53DA6B97", "Application Load Balancers per Region"),
    ("rds", "L-7B6409FD", "DB instances"),
    ("lambda", "L-B99A9384", "Concurrent executions"),
)


def _quota_value(sq, service_code: str, quota_code: str):
    try:
        return sq.get_service_quota(ServiceCode=service_code, QuotaCode=quota_code)["Quota"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"AccessDeniedException", "AccessDenied"}:
            raise
        try:
            return sq.get_aws_default_service_quota(ServiceCode=service_code, QuotaCode=quota_code)["Quota"]
        except ClientError:
            return None


@ignore_access_denied(default=list)
def common_quota_values(ctx: AwsContext, region: str) -> list[dict]:
    sq = ctx.client("service-quotas", region=region)
    results = []
    for service_code, quota_code, label in COMMON_QUOTAS:
        quota = _quota_value(sq, service_code, quota_code)
        if quota:
            results.append(
                {
                    "ServiceCode": service_code,
                    "QuotaCode": quota_code,
                    "Label": label,
                    "Value": quota.get("Value"),
                    "Unit": quota.get("Unit"),
                    "Adjustable": quota.get("Adjustable"),
                }
            )
    return results


@ignore_access_denied(default=list)
def pending_quota_increase_requests(ctx: AwsContext, region: str) -> list[dict]:
    sq = ctx.client("service-quotas", region=region)
    return list(
        paginate(
            sq,
            "list_requested_service_quota_change_history",
            "RequestedQuotas",
            Status="PENDING",
        )
    )
