"""Security posture: GuardDuty, Security Hub, IAM, Access Analyzer, AWS Config."""
from __future__ import annotations

import csv
import io
import time

from ..session import AwsContext, ignore_access_denied, paginate


# ---------------------------------------------------------------- GuardDuty
@ignore_access_denied(default=list)
def guardduty_detector_ids(ctx: AwsContext, region: str) -> list[str]:
    gd = ctx.client("guardduty", region=region)
    return list(paginate(gd, "list_detectors", "DetectorIds"))


@ignore_access_denied(default=list)
def guardduty_findings(ctx: AwsContext, region: str, max_findings: int = 200) -> list[dict]:
    """Paginates `list_findings` fully (up to `max_findings` total across
    every detector) rather than only the first page -- a detector with
    more than one page of active findings would otherwise be silently
    under-reported."""
    gd = ctx.client("guardduty", region=region)
    findings = []
    for detector_id in guardduty_detector_ids(ctx, region):
        remaining = max_findings - len(findings)
        if remaining <= 0:
            break
        finding_ids = []
        for finding_id in paginate(gd, "list_findings", "FindingIds", DetectorId=detector_id):
            finding_ids.append(finding_id)
            if len(finding_ids) >= remaining:
                break
        for i in range(0, len(finding_ids), 50):
            batch = finding_ids[i : i + 50]
            details = gd.get_findings(DetectorId=detector_id, FindingIds=batch)["Findings"]
            findings.extend(details)
            if len(findings) >= max_findings:
                break
    return findings[:max_findings]


def guardduty_status(ctx: AwsContext, region: str) -> dict:
    detector_ids = guardduty_detector_ids(ctx, region)
    return {"Region": region, "Enabled": bool(detector_ids), "DetectorIds": detector_ids}


# --------------------------------------------------------------- SecurityHub
@ignore_access_denied(default=lambda: {"Enabled": False})
def securityhub_status(ctx: AwsContext, region: str) -> dict:
    sh = ctx.client("securityhub", region=region)
    hub = sh.describe_hub()
    standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
    return {"Enabled": True, "HubArn": hub.get("HubArn"), "EnabledStandards": standards}


@ignore_access_denied(default=list)
def securityhub_findings(
    ctx: AwsContext, region: str, severity_labels: tuple[str, ...] = ("CRITICAL", "HIGH"), max_findings: int = 200
) -> list[dict]:
    sh = ctx.client("securityhub", region=region)
    filters = {
        "SeverityLabel": [{"Value": s, "Comparison": "EQUALS"} for s in severity_labels],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    }
    findings = []
    for finding in paginate(sh, "get_findings", "Findings", Filters=filters):
        findings.append(finding)
        if len(findings) >= max_findings:
            break
    return findings


@ignore_access_denied(default=list)
def securityhub_standards_summary(ctx: AwsContext, region: str) -> list[dict]:
    """Pass/fail control counts per enabled standard (CIS, FSBP, PCI, etc.)."""
    sh = ctx.client("securityhub", region=region)
    subs = sh.get_enabled_standards().get("StandardsSubscriptions", [])
    summaries = []
    for sub in subs:
        controls = list(
            paginate(
                sh,
                "describe_standards_controls",
                "Controls",
                StandardsSubscriptionArn=sub["StandardsSubscriptionArn"],
            )
        )
        enabled = [c for c in controls if c.get("ControlStatus") == "ENABLED"]
        summaries.append(
            {
                "StandardsArn": sub["StandardsArn"],
                "ControlCount": len(controls),
                "EnabledControlCount": len(enabled),
            }
        )
    return summaries


# --------------------------------------------------------------------- IAM
def iam_credential_report(ctx: AwsContext) -> list[dict]:
    iam = ctx.client("iam")
    for _ in range(10):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(1)
    report = iam.get_credential_report()
    text = report["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(text)))


def iam_password_policy(ctx: AwsContext) -> dict | None:
    iam = ctx.client("iam")
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return None


def iam_users(ctx: AwsContext) -> list[dict]:
    iam = ctx.client("iam")
    users = list(paginate(iam, "list_users", "Users"))
    for user in users:
        user["_MfaDevices"] = iam.list_mfa_devices(UserName=user["UserName"]).get(
            "MFADevices", []
        )
        user["_AttachedPolicies"] = iam.list_attached_user_policies(
            UserName=user["UserName"]
        ).get("AttachedPolicies", [])
        user["_AccessKeys"] = iam.list_access_keys(UserName=user["UserName"]).get(
            "AccessKeyMetadata", []
        )
    return users


def iam_roles(ctx: AwsContext) -> list[dict]:
    iam = ctx.client("iam")
    return list(paginate(iam, "list_roles", "Roles"))


def iam_findings(credential_report: list[dict], password_policy: dict | None) -> dict:
    stale_keys = []
    no_mfa_console_users = []
    root_risk = []
    for row in credential_report:
        user = row.get("user", "")
        if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
            no_mfa_console_users.append(user)
        for key_n in ("1", "2"):
            active = row.get(f"access_key_{key_n}_active") == "true"
            last_rotated = row.get(f"access_key_{key_n}_last_rotated")
            if active and last_rotated and last_rotated != "N/A":
                stale_keys.append({"user": user, "key": key_n, "last_rotated": last_rotated})
        if user == "<root_account>":
            if row.get("mfa_active") == "false":
                root_risk.append("root account has no MFA")
            if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                root_risk.append("root account has an active access key")
    return {
        "ConsoleUsersWithoutMfa": no_mfa_console_users,
        "AccessKeysToReview": stale_keys,
        "RootAccountRisks": root_risk,
        "PasswordPolicySet": password_policy is not None,
    }


# --------------------------------------------------------------- IAM Access Analyzer
@ignore_access_denied(default=list)
def access_analyzer_findings(ctx: AwsContext, region: str) -> list[dict]:
    aa = ctx.client("accessanalyzer", region=region)
    analyzers = list(paginate(aa, "list_analyzers", "analyzers"))
    findings = []
    for analyzer in analyzers:
        findings.extend(
            paginate(
                aa,
                "list_findings",
                "findings",
                analyzerArn=analyzer["arn"],
                filter={"status": {"eq": ["ACTIVE"]}},
            )
        )
    return findings


# --------------------------------------------------------------------- Config
@ignore_access_denied(default=list)
def config_rule_compliance(ctx: AwsContext, region: str) -> list[dict]:
    cfg = ctx.client("config", region=region)
    return list(
        paginate(
            cfg, "describe_compliance_by_config_rule", "ComplianceByConfigRules"
        )
    )


@ignore_access_denied(default=lambda: {"Recorders": [], "Recording": False})
def config_recorder_status(ctx: AwsContext, region: str) -> dict:
    """Whether the Config recorder itself is even set up and running --
    rule compliance is meaningless if the recorder isn't recording."""
    cfg = ctx.client("config", region=region)
    recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    statuses = cfg.describe_configuration_recorder_status().get(
        "ConfigurationRecordersStatus", []
    )
    recording = any(s.get("recording") for s in statuses)
    return {"Recorders": recorders, "Statuses": statuses, "Recording": recording}


def collect_region_security(ctx: AwsContext, region: str) -> dict:
    return {
        "Region": region,
        "GuardDuty": guardduty_status(ctx, region),
        "GuardDutyFindings": guardduty_findings(ctx, region),
        "SecurityHub": securityhub_status(ctx, region),
        "SecurityHubFindings": securityhub_findings(ctx, region),
        "SecurityHubStandardsSummary": securityhub_standards_summary(ctx, region),
        "AccessAnalyzerFindings": access_analyzer_findings(ctx, region),
        "ConfigRuleCompliance": config_rule_compliance(ctx, region),
        "ConfigRecorder": config_recorder_status(ctx, region),
    }


def collect_global_security(ctx: AwsContext) -> dict:
    credential_report = iam_credential_report(ctx)
    password_policy = iam_password_policy(ctx)
    return {
        "IamUsers": iam_users(ctx),
        "IamRoles": iam_roles(ctx),
        "IamCredentialReport": credential_report,
        "IamPasswordPolicy": password_policy,
        "IamFindings": iam_findings(credential_report, password_policy),
    }
