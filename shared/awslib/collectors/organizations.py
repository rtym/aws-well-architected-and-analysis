"""AWS Organizations posture: is this account part of an org, what accounts
exist, what Service Control Policies are attached, which accounts are
delegated administrators for security services, and whether GuardDuty/
Security Hub are actually managed org-wide (a central admin account with
every member auto-enrolled) versus configured independently per account.

Must be run against the Organizations management account or a delegated
administrator account -- a plain member account will get
AWSOrganizationsNotInUseException-adjacent AccessDenied errors for most of
this, which `not_in_organization()` distinguishes from a real permissions
gap.
"""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..session import AwsContext, ignore_access_denied, paginate

NOT_IN_ORG_ERROR_CODES = {
    "AWSOrganizationsNotInUseException",
    "AccessDeniedException",
}


def is_organizations_member(ctx: AwsContext) -> bool:
    """True if this account belongs to an Organization at all (management
    or member account) -- False if it's a standalone account, OR if this
    identity simply lacks `organizations:DescribeOrganization` (a locked-
    down member account's IAM policy can produce the same AccessDenied a
    standalone account would). Either way, the honest answer this function
    can give is "no organization visibility from here" -- it can't always
    tell the two cases apart, so it doesn't claim to."""
    org = ctx.client("organizations", region="us-east-1")
    try:
        org.describe_organization()
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in NOT_IN_ORG_ERROR_CODES:
            return False
        raise


@ignore_access_denied(default=lambda: None)
def describe_organization(ctx: AwsContext) -> dict | None:
    org = ctx.client("organizations", region="us-east-1")
    try:
        return org.describe_organization()["Organization"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in NOT_IN_ORG_ERROR_CODES:
            return None
        raise


@ignore_access_denied(default=list)
def list_accounts(ctx: AwsContext) -> list[dict]:
    org = ctx.client("organizations", region="us-east-1")
    return list(paginate(org, "list_accounts", "Accounts"))


@ignore_access_denied(default=list)
def list_service_control_policies(ctx: AwsContext) -> list[dict]:
    org = ctx.client("organizations", region="us-east-1")
    policies = list(
        paginate(org, "list_policies", "Policies", Filter="SERVICE_CONTROL_POLICY")
    )
    for policy in policies:
        targets = list(
            paginate(org, "list_targets_for_policy", "Targets", PolicyId=policy["Id"])
        )
        policy["_Targets"] = targets
    return policies


@ignore_access_denied(default=list)
def list_delegated_administrators(ctx: AwsContext, service_principal: str | None = None) -> list[dict]:
    org = ctx.client("organizations", region="us-east-1")
    kwargs = {"ServicePrincipal": service_principal} if service_principal else {}
    return list(paginate(org, "list_delegated_administrators", "DelegatedAdministrators", **kwargs))


@ignore_access_denied(default=lambda: None)
def guardduty_organization_admin(ctx: AwsContext, region: str) -> dict | None:
    gd = ctx.client("guardduty", region=region)
    admins = gd.list_organization_admin_accounts().get("AdminAccounts", [])
    return admins[0] if admins else None


@ignore_access_denied(default=lambda: None)
def securityhub_organization_admin(ctx: AwsContext, region: str) -> dict | None:
    sh = ctx.client("securityhub", region=region)
    admins = sh.list_organization_admin_accounts().get("AdminAccounts", [])
    return admins[0] if admins else None


def accounts_without_scp_coverage(accounts: list[dict], policies: list[dict]) -> list[dict]:
    covered_ids = set()
    for policy in policies:
        for target in policy.get("_Targets", []):
            if target.get("Type") == "ACCOUNT":
                covered_ids.add(target.get("TargetId"))
    return [a for a in accounts if a.get("Id") not in covered_ids]


def collect_organization_posture(ctx: AwsContext, home_region: str) -> dict:
    if not is_organizations_member(ctx):
        return {"IsOrganizationsMember": False}

    accounts = list_accounts(ctx)
    policies = list_service_control_policies(ctx)
    return {
        "IsOrganizationsMember": True,
        "Organization": describe_organization(ctx),
        "Accounts": accounts,
        "ServiceControlPolicies": policies,
        "AccountsWithoutScpCoverage": accounts_without_scp_coverage(accounts, policies),
        "DelegatedAdministrators": list_delegated_administrators(ctx),
        "GuardDutyOrganizationAdmin": guardduty_organization_admin(ctx, home_region),
        "SecurityHubOrganizationAdmin": securityhub_organization_admin(ctx, home_region),
    }
