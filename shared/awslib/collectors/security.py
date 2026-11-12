"""Security posture: GuardDuty, Security Hub, Inspector, Macie, IAM,
Access Analyzer, AWS Config, and encryption/exposure checks (EBS, KMS,
Lambda function URLs, account-level S3 Block Public Access)."""
from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from ..session import AwsContext, ignore_access_denied, paginate


# ---------------------------------------------------------------- GuardDuty
@ignore_access_denied(default=list)
def guardduty_detector_ids(ctx: AwsContext, region: str) -> list[str]:
    gd = ctx.client("guardduty", region=region)
    return list(paginate(gd, "list_detectors", "DetectorIds"))


# ListFindings returns archived findings too unless told otherwise, and
# suppression rules archive findings automatically -- so without this filter
# the report would resurface exactly the noise the account owner silenced.
GUARDDUTY_UNARCHIVED = {"Criterion": {"service.archived": {"Eq": ["false"]}}}
GUARDDUTY_MOST_SEVERE_FIRST = {"AttributeName": "severity", "OrderBy": "DESC"}


def guardduty_severity_label(score: float) -> str:
    """GuardDuty's documented severity bands: Critical 9.0-10.0 (attack
    sequences from Extended Threat Detection), High 7.0-8.9, Medium
    4.0-6.9, Low below 4.0."""
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


@ignore_access_denied(default=list)
def guardduty_findings(ctx: AwsContext, region: str, max_findings: int = 200) -> list[dict]:
    """Unarchived findings, most severe first, paginated fully (up to
    `max_findings` total across every detector) -- a detector with more
    than one page of findings would otherwise be silently under-reported,
    and sorting server-side means the cap drops the least severe ones."""
    gd = ctx.client("guardduty", region=region)
    findings = []
    for detector_id in guardduty_detector_ids(ctx, region):
        remaining = max_findings - len(findings)
        if remaining <= 0:
            break
        finding_ids = []
        for finding_id in paginate(
            gd,
            "list_findings",
            "FindingIds",
            DetectorId=detector_id,
            FindingCriteria=GUARDDUTY_UNARCHIVED,
            SortCriteria=GUARDDUTY_MOST_SEVERE_FIRST,
        ):
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
        # NOTIFIED means "owner told, not yet fixed" -- still open. Only
        # RESOLVED and SUPPRESSED are closed states.
        "WorkflowStatus": [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ],
    }
    findings = []
    for finding in paginate(sh, "get_findings", "Findings", Filters=filters):
        findings.append(finding)
        if len(findings) >= max_findings:
            break
    return findings


@ignore_access_denied(default=list)
def securityhub_standards_summary(ctx: AwsContext, region: str) -> list[dict]:
    """Enabled vs. total control counts per subscribed standard (CIS,
    FSBP, PCI, etc.). This measures how much of a standard is switched
    on, not how many controls pass -- pass/fail lives in the findings."""
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
CREDENTIAL_REPORT_ATTEMPTS = 30
CREDENTIAL_REPORT_WAIT_SECONDS = 2

def iam_credential_report(ctx: AwsContext) -> list[dict]:
    """The IAM credential report, generated on demand. AWS usually finishes
    it in a few seconds but can take longer in an account with many users;
    ten one-second tries gave up early there and the read that followed
    failed with ReportInProgress. Waits up to a minute now."""
    iam = ctx.client("iam")
    for _ in range(CREDENTIAL_REPORT_ATTEMPTS):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(CREDENTIAL_REPORT_WAIT_SECONDS)
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


def _key_age_days(last_rotated: str) -> int | None:
    """Age of a credential-report timestamp (ISO 8601) in days; None when the
    value isn't a date ("N/A", "no_information")."""
    try:
        rotated = datetime.fromisoformat(last_rotated)
    except ValueError:
        return None
    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - rotated).days


def iam_findings(
    credential_report: list[dict], password_policy: dict | None, max_key_age_days: int = 90
) -> dict:
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
            if not active or not last_rotated or last_rotated == "N/A":
                continue
            # FSBP IAM.3: rotate access keys every 90 days or less. A key
            # whose rotation date can't be parsed ("no_information") is
            # reported too -- unknown age is not evidence of freshness.
            age = _key_age_days(last_rotated)
            if age is None or age > max_key_age_days:
                stale_keys.append(
                    {"user": user, "key": key_n, "last_rotated": last_rotated, "age_days": age}
                )
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
@ignore_access_denied(default=lambda: None)
def access_analyzers(ctx: AwsContext, region: str) -> list[dict] | None:
    """The analyzers in the region (name, type, status), or None when they
    couldn't be listed. Zero analyzers means zero findings proves nothing,
    so the security checks need this alongside the findings."""
    aa = ctx.client("accessanalyzer", region=region)
    return [
        {"arn": a["arn"], "name": a.get("name"), "type": a.get("type"), "status": a.get("status")}
        for a in paginate(aa, "list_analyzers", "analyzers")
    ]


@ignore_access_denied(default=list)
def access_analyzer_findings(ctx: AwsContext, region: str, analyzers: list[dict] | None = None) -> list[dict]:
    """Active findings from every analyzer in the region. Uses
    ListFindingsV2: the original ListFindings only covers external-access
    analyzers, while unused-access and internal-access findings are
    available only through V2 (same IAM action, access-analyzer:ListFindings).
    Pass the region's `access_analyzers()` result to skip listing them again."""
    aa = ctx.client("accessanalyzer", region=region)
    if analyzers is None:
        analyzers = list(paginate(aa, "list_analyzers", "analyzers"))
    findings = []
    for analyzer in analyzers:
        findings.extend(
            paginate(
                aa,
                "list_findings_v2",
                "findings",
                analyzerArn=analyzer["arn"],
                filter={"status": {"eq": ["ACTIVE"]}},
            )
        )
    return findings


# ----------------------------------------------------------- EBS encryption
@ignore_access_denied(default=lambda: None)
def ebs_encryption_by_default(ctx: AwsContext, region: str) -> bool | None:
    """Whether new EBS volumes in this region are encrypted automatically
    (FSBP EC2.7). None when the answer couldn't be read."""
    ec2 = ctx.client("ec2", region=region)
    return ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]


@ignore_access_denied(default=list)
def unencrypted_ebs_volumes(ctx: AwsContext, region: str) -> list[dict]:
    """EBS volumes without encryption at rest (FSBP EC2.3)."""
    ec2 = ctx.client("ec2", region=region)
    return [
        {"VolumeId": v["VolumeId"], "State": v.get("State"), "SizeGiB": v.get("Size")}
        for v in paginate(ec2, "describe_volumes", "Volumes")
        if not v.get("Encrypted")
    ]


@ignore_access_denied(default=list)
def public_ebs_snapshots(ctx: AwsContext, region: str) -> list[dict]:
    """Snapshots this account owns that anyone can restore (FSBP EC2.1)."""
    ec2 = ctx.client("ec2", region=region)
    return [
        {"SnapshotId": s["SnapshotId"], "VolumeId": s.get("VolumeId")}
        for s in paginate(
            ec2, "describe_snapshots", "Snapshots",
            OwnerIds=["self"], RestorableByUserIds=["all"],
        )
    ]


# ----------------------------------------------------------------------- KMS
@ignore_access_denied(default=list)
def kms_keys_without_rotation(ctx: AwsContext, region: str) -> list[dict]:
    """Enabled, customer-managed symmetric KMS keys with automatic rotation
    off (FSBP KMS.4). AWS-managed keys rotate automatically; asymmetric
    keys, and keys whose material is imported or held in a custom key
    store, can't auto-rotate -- none of those are listed."""
    kms = ctx.client("kms", region=region)
    flagged = []
    for key in paginate(kms, "list_keys", "Keys"):
        try:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                continue
            if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            if meta.get("Origin", "AWS_KMS") != "AWS_KMS":
                continue
            rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
            if not rotation.get("KeyRotationEnabled"):
                flagged.append(
                    {"KeyId": key["KeyId"], "Description": meta.get("Description", "")}
                )
        except ClientError as exc:
            # A key's own policy can deny Describe/GetKeyRotationStatus even
            # when ListKeys succeeds -- skip that key, keep scanning the rest.
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"AccessDenied", "AccessDeniedException"}:
                # Named in the evidence: a key nobody could read is not a
                # key that rotates.
                ctx.record_denied("kms_keys_without_rotation", region, code, exc.operation_name, key["KeyId"])
                continue
            if code == "NotFoundException":
                continue
            raise
    return flagged


# -------------------------------------------------------- Lambda function URLs
@ignore_access_denied(default=list)
def lambda_urls_without_auth(ctx: AwsContext, region: str) -> list[dict]:
    """Lambda function URLs with AuthType NONE -- callable by anyone on the
    internet without signed requests. Lists every URL config per function,
    because an alias can carry its own URL separate from the function's."""
    lam = ctx.client("lambda", region=region)
    flagged = []
    for fn in paginate(lam, "list_functions", "Functions"):
        for cfg in paginate(
            lam, "list_function_url_configs", "FunctionUrlConfigs", FunctionName=fn["FunctionName"]
        ):
            if cfg.get("AuthType") == "NONE":
                flagged.append(
                    {"FunctionName": fn["FunctionName"], "FunctionUrl": cfg.get("FunctionUrl")}
                )
    return flagged


# -------------------------------------------------------- Inspector and Macie
@ignore_access_denied(default=lambda: {"Enabled": False, "Status": None})
def inspector2_status(ctx: AwsContext, region: str) -> dict:
    """Whether Amazon Inspector (vulnerability scanning) is on in a region."""
    insp = ctx.client("inspector2", region=region)
    accounts = insp.batch_get_account_status(accountIds=[ctx.account_id()]).get("accounts", [])
    status = accounts[0].get("state", {}).get("status") if accounts else None
    return {"Enabled": status == "ENABLED", "Status": status}


@ignore_access_denied(default=lambda: {"Enabled": False, "Status": None})
def macie_status(ctx: AwsContext, region: str) -> dict:
    """Whether Amazon Macie (S3 sensitive-data discovery) is on in a region.
    When Macie has never been enabled the API raises AccessDeniedException
    with the message "Macie is not enabled", which is an answer (off), not
    a permissions gap; any other AccessDeniedException is recorded as one."""
    macie = ctx.client("macie2", region=region)
    try:
        session_info = macie.get_macie_session()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        if error.get("Code") == "AccessDeniedException" and "not enabled" in (error.get("Message") or "").lower():
            return {"Enabled": False, "Status": None}
        raise
    return {"Enabled": session_info.get("status") == "ENABLED", "Status": session_info.get("status")}


# ------------------------------------------- Account-level S3 public access
@ignore_access_denied(default=lambda: None)
def account_public_access_block(ctx: AwsContext) -> dict | None:
    """The account-wide S3 Block Public Access configuration (FSBP S3.1).
    Per-bucket settings (collected in data_stores) can be loosened bucket by
    bucket; this account-level switch is the backstop. None = not set."""
    s3control = ctx.client("s3control")
    try:
        return s3control.get_public_access_block(AccountId=ctx.account_id())[
            "PublicAccessBlockConfiguration"
        ]
    except s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
        return None


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
    analyzers = access_analyzers(ctx, region)
    return {
        "Region": region,
        "GuardDuty": guardduty_status(ctx, region),
        "GuardDutyFindings": guardduty_findings(ctx, region),
        "SecurityHub": securityhub_status(ctx, region),
        "SecurityHubFindings": securityhub_findings(ctx, region),
        "SecurityHubStandardsSummary": securityhub_standards_summary(ctx, region),
        "Inspector2": inspector2_status(ctx, region),
        "Macie": macie_status(ctx, region),
        "AccessAnalyzers": analyzers,
        "AccessAnalyzerFindings": access_analyzer_findings(ctx, region, analyzers),
        "ConfigRuleCompliance": config_rule_compliance(ctx, region),
        "ConfigRecorder": config_recorder_status(ctx, region),
        "EbsEncryptionByDefault": ebs_encryption_by_default(ctx, region),
        "UnencryptedEbsVolumes": unencrypted_ebs_volumes(ctx, region),
        "PublicEbsSnapshots": public_ebs_snapshots(ctx, region),
        "KmsKeysWithoutRotation": kms_keys_without_rotation(ctx, region),
        "LambdaUrlsWithoutAuth": lambda_urls_without_auth(ctx, region),
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
