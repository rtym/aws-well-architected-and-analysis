"""AWS Backup coverage: plans, vaults (incl. cross-region/cross-account copy
destinations configured on plan rules), and recent job success/failure --
the centralized backup posture, as distinct from a single service's own
snapshot fields (e.g. RDS automated backups, checked separately in
data_stores.py).
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


@ignore_access_denied(default=list)
def list_backup_plans(ctx: AwsContext, region: str) -> list[dict]:
    backup = ctx.client("backup", region=region)
    summaries = list(paginate(backup, "list_backup_plans", "BackupPlansList"))
    plans = []
    for summary in summaries:
        detail = backup.get_backup_plan(BackupPlanId=summary["BackupPlanId"])
        plans.append({**summary, "_Rules": detail["BackupPlan"].get("Rules", [])})
    return plans


@ignore_access_denied(default=list)
def list_backup_vaults(ctx: AwsContext, region: str) -> list[dict]:
    backup = ctx.client("backup", region=region)
    return list(paginate(backup, "list_backup_vaults", "BackupVaultList"))


@ignore_access_denied(default=list)
def list_protected_resources(ctx: AwsContext, region: str) -> list[dict]:
    backup = ctx.client("backup", region=region)
    return list(paginate(backup, "list_protected_resources", "Results"))


@ignore_access_denied(default=list)
def list_recent_jobs(ctx: AwsContext, region: str, by_state: str | None = None) -> list[dict]:
    backup = ctx.client("backup", region=region)
    kwargs = {"ByState": by_state} if by_state else {}
    return list(paginate(backup, "list_backup_jobs", "BackupJobs", **kwargs))


def _vault_region(vault_arn: str) -> str | None:
    """"arn:aws:backup:eu-west-1:123456789012:backup-vault:dr" -> "eu-west-1"."""
    parts = (vault_arn or "").split(":")
    return parts[3] if len(parts) > 3 and parts[3] else None


def plans_with_cross_region_copy(plans: list[dict], region: str) -> list[dict]:
    """Plans in `region` with a rule that copies recovery points to a vault
    in another region. A copy to another vault in the same region (another
    account's, or a logically air-gapped one) is a copy, but it doesn't
    survive a regional outage, and counting it passed the cross-region check."""
    matches = []
    for plan in plans:
        rules = [
            rule
            for rule in plan.get("_Rules", [])
            if any(
                _vault_region(action.get("DestinationBackupVaultArn")) not in (None, region)
                for action in rule.get("CopyActions") or []
            )
        ]
        if rules:
            matches.append({"BackupPlanId": plan["BackupPlanId"], "BackupPlanName": plan.get("BackupPlanName"), "Rules": rules})
    return matches


def collect_region_backup(ctx: AwsContext, region: str) -> dict:
    plans = list_backup_plans(ctx, region)
    return {
        "Region": region,
        "BackupPlans": plans,
        "BackupVaults": list_backup_vaults(ctx, region),
        "ProtectedResources": list_protected_resources(ctx, region),
        "FailedJobsRecent": list_recent_jobs(ctx, region, by_state="FAILED"),
        "PlansWithCrossRegionCopy": plans_with_cross_region_copy(plans, region),
    }
