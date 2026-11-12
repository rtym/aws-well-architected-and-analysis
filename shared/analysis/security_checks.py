"""The security review's check catalog, attack-path correlations, and
threat triage, evaluated against the evidence bundle that
`skills/aws-security-review/scripts/security_scan.py` collects.

Severities follow the Security Hub control each check implements (verified
against the Security Hub controls reference, 2026-11-07). Checks without a
Security Hub control carry a plugin-assigned severity, documented in
`skills/aws-security-review/references/severity-and-standards.md`.

Every evaluator returns None when the evidence it needs is missing (for
example a JSON file written by an older plugin version), so old evidence
scores as NO DATA instead of as a false PASS.
"""
from __future__ import annotations

from . import access
from .checks import (
    NO_DATA,
    AttackPath,
    Affected,
    Check,
    CheckResult,
    Threat,
    evaluate,
    prioritize,
    score,
)

DETECTION = "Detection and logging"
IDENTITY = "Identity and access"
NETWORK = "Network exposure"
DATA = "Data protection"
DOMAINS = (DETECTION, IDENTITY, NETWORK, DATA)
# At equal severity, fix what is exposed now before what limits visibility.
PRIORITY_DOMAINS = (NETWORK, DATA, IDENTITY, DETECTION)

# Security Hub EC2.19: ports considered high risk when open to 0.0.0.0/0 or
# ::/0 (FTP, SSH, Telnet, SMTP, POP3, RPC, IMAP, CIFS, MSSQL, web dev
# frameworks, MySQL, RDP, PostgreSQL, OpenSearch, proxies).
HIGH_RISK_PORTS = (
    20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389,
    4333, 5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300,
)
# Security Hub EC2.18 default: only 80 and 443 (TCP) may be open to the world.
AUTHORIZED_TCP_PORTS = (80, 443)

ROOT_KEY_RISK = "root account has an active access key"
ROOT_MFA_RISK = "root account has no MFA"
BPA_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


# Where each collector's evidence sits in a region of the bundle. When a
# call was denied (`AccessDenied` in the evidence), these keys are removed
# before the checks run: the collector returned its empty default, which
# would otherwise score as "nothing found" (a PASS) or "service off" (a FAIL).
DENIED_REGION_EVIDENCE = {
    "guardduty_detector_ids": (("Security", "GuardDuty"), ("Security", "GuardDutyFindings")),
    "guardduty_findings": (("Security", "GuardDutyFindings"),),
    "securityhub_status": (("Security", "SecurityHub"),),
    "securityhub_findings": (("Security", "SecurityHubFindings"),),
    "inspector2_status": (("Security", "Inspector2"),),
    "macie_status": (("Security", "Macie"),),
    "access_analyzer_findings": (("Security", "AccessAnalyzerFindings"),),
    "config_recorder_status": (("Security", "ConfigRecorder"),),
    "unencrypted_ebs_volumes": (("Security", "UnencryptedEbsVolumes"),),
    "public_ebs_snapshots": (("Security", "PublicEbsSnapshots"),),
    "kms_keys_without_rotation": (("Security", "KmsKeysWithoutRotation"),),
    "lambda_urls_without_auth": (("Security", "LambdaUrlsWithoutAuth"),),
    "describe_rds_instances": (("RdsExposure",),),
    "describe_rds_snapshots": (("PublicRdsSnapshots",),),
    "public_rds_snapshots": (("PublicRdsSnapshots",),),
    "public_rds_cluster_snapshots": (("PublicRdsSnapshots",),),
    "describe_acm_certificates": (("Compute", "ExpiringCertificates"),),
}
# The same for account-wide evidence, under `Global`.
DENIED_GLOBAL_EVIDENCE = {
    "describe_trails": (("CloudTrail",),),
    "account_public_access_block": (("AccountPublicAccessBlock",),),
}
DENIED_NOTE = "Not evaluated: the scan was denied access to evidence this check needs (see Access Gaps)."
PARTIAL_NOTE = "Evaluated only where the evidence could be read; part of it was denied (see Access Gaps)."

# A region where a check doesn't apply, as opposed to one whose evidence is
# missing: it neither fails the check nor stops the other regions passing it.
_NOT_APPLICABLE = object()


def _without(node: dict, path: tuple[str, ...]) -> dict:
    """A copy of `node` with the key at `path` removed; only the dicts along
    the path are copied."""
    if not isinstance(node, dict) or path[0] not in node:
        return node
    out = dict(node)
    if len(path) == 1:
        del out[path[0]]
    else:
        out[path[0]] = _without(node[path[0]], path[1:])
    return out


def readable_evidence(data: dict) -> dict:
    """The evidence with everything a denied call would have filled taken
    out, so a check reads it as missing. Returns `data` itself when nothing
    was denied."""
    denied = access.denied(data)
    if not denied:
        return data
    regions = dict(_regions(data))
    global_data = _global(data)
    for entry in denied:
        collector, region = entry.get("Collector"), entry.get("Region")
        for path in DENIED_REGION_EVIDENCE.get(collector, ()):
            if region in regions:
                regions[region] = _without(regions[region], path)
        for path in DENIED_GLOBAL_EVIDENCE.get(collector, ()):
            global_data = _without(global_data, path)
    return {**data, "Regions": regions, "Global": global_data}


# ------------------------------------------------------------ evidence access
def _regions(data: dict) -> dict:
    return data.get("Regions") or {}


def _global(data: dict) -> dict:
    return data.get("Global") or {}


def _per_region(data: dict, getter) -> list[Affected] | None:
    """Collect affected resources region by region. `getter(region,
    region_data)` returns a list of Affected, None for "no evidence in this
    region", or `_NOT_APPLICABLE`. Anything affected is a FAIL wherever it
    was found. A PASS needs evidence from every region the check applies
    to: one unread region makes the result None (NO DATA), because "in
    every scanned region" can't be claimed past a region nobody read."""
    regions = _regions(data)
    if not regions:
        return None
    affected: list[Affected] = []
    saw_evidence = missing = False
    for region, region_data in regions.items():
        found = getter(region, region_data)
        if found is _NOT_APPLICABLE:
            continue
        if found is None:
            missing = True
            continue
        saw_evidence = True
        affected.extend(found)
    if affected:
        return affected
    return [] if saw_evidence and not missing else None


def _security(region_data: dict) -> dict:
    return region_data.get("Security") or {}


def _service_off(key: str, flag: str = "Enabled"):
    def getter(region, region_data):
        status = _security(region_data).get(key)
        if status is None:
            return None
        return [] if status.get(flag) else [Affected(region, region, "not enabled")]

    return getter


def _list_items(path: tuple[str, ...], resource_key: str, detail=lambda item: ""):
    """Affected resources from a list found at `path` inside region data."""

    def getter(region, region_data):
        node = region_data
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        if node is None:
            return None
        return [Affected(str(item.get(resource_key, "?")), region, detail(item)) for item in node]

    return getter


# -------------------------------------------------------- security groups
def _proto(rule: dict) -> str:
    return {"6": "tcp", "17": "udp", "-1": "all"}.get(str(rule.get("IpProtocol")), str(rule.get("IpProtocol")))


def _port_text(rule: dict) -> str:
    if _proto(rule) == "all" or rule.get("FromPort") is None:
        return "all ports"
    if rule.get("FromPort") == rule.get("ToPort"):
        return str(rule.get("FromPort"))
    return f"{rule.get('FromPort')}-{rule.get('ToPort')}"


def _rule_text(rule: dict) -> str:
    proto = _proto(rule)
    ports = _port_text(rule)
    ranges = ", ".join(rule.get("OpenRanges") or [])
    return f"{ports}/{proto} from {ranges}" if proto != "all" else f"all traffic from {ranges}"


def _covers(rule: dict, port: int) -> bool:
    proto = _proto(rule)
    if proto == "all":
        return True
    if proto not in ("tcp", "udp"):
        return False
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None:
        return True
    return low <= port <= high


def high_risk_ports_in(rule: dict) -> list[int]:
    return [p for p in HIGH_RISK_PORTS if _covers(rule, p)]


def opens_unauthorized_port(rule: dict) -> bool:
    """EC2.18 with its default parameters: an internet-open rule fails
    unless it is TCP and limited to exactly port 80 or 443."""
    proto = _proto(rule)
    if proto == "all" or proto == "udp":
        return True
    if proto != "tcp":
        return False
    low, high = rule.get("FromPort"), rule.get("ToPort")
    return not (low is not None and low == high and low in AUTHORIZED_TCP_PORTS)


def _sg_rules(region_data: dict) -> list[dict] | None:
    return region_data.get("WideOpenSecurityGroups")


def _high_risk_rules(region, region_data):
    rules = _sg_rules(region_data)
    if rules is None:
        return None
    return [Affected(r.get("GroupId", "?"), region, _rule_text(r)) for r in rules if high_risk_ports_in(r)]


def _unauthorized_rules(region, region_data):
    rules = _sg_rules(region_data)
    if rules is None:
        return None
    return [Affected(r.get("GroupId", "?"), region, _rule_text(r)) for r in rules if opens_unauthorized_port(r)]


# -------------------------------------------------------------- evaluators
def _guardduty(data):
    return _per_region(data, _service_off("GuardDuty"))


def _securityhub(data):
    return _per_region(data, _service_off("SecurityHub"))


def _inspector(data):
    return _per_region(data, _service_off("Inspector2"))


def _macie(data):
    return _per_region(data, _service_off("Macie"))


def _config(data):
    def getter(region, region_data):
        recorder = _security(region_data).get("ConfigRecorder")
        if recorder is None:
            return None
        return [] if recorder.get("Recording") else [Affected(region, region, "recorder not recording")]

    return _per_region(data, getter)


def _cloudtrail(data):
    ct = _global(data).get("CloudTrail")
    if ct is None:
        return None
    ok = ct.get("HasLoggingMultiRegionTrail")
    if ok is None:  # evidence from before 1.4.1
        ok = ct.get("HasMultiRegionTrail") and ct.get("HasLoggingTrail")
    return [] if ok else [Affected("account", "global", "no multi-region trail is logging")]


def _cloudtrail_validation(data):
    ct = _global(data).get("CloudTrail")
    if ct is None or not ct.get("Trails"):
        return None
    return [
        Affected(t.get("Name", "?"), t.get("HomeRegion", "global"), "log file validation off")
        for t in ct["Trails"]
        if not t.get("LogFileValidationEnabled")
    ]


def _iam(data) -> dict | None:
    return _global(data).get("IamFindings")


def _root_risk(risk: str):
    def evaluator(data):
        findings = _iam(data)
        if findings is None:
            return None
        return [Affected("root user", "global", risk)] if risk in findings.get("RootAccountRisks", []) else []

    return evaluator


def _console_mfa(data):
    findings = _iam(data)
    if findings is None:
        return None
    return [Affected(u, "global", "console password, no MFA") for u in findings.get("ConsoleUsersWithoutMfa", [])]


def _key_age(data):
    findings = _iam(data)
    if findings is None:
        return None
    rows = []
    for k in findings.get("AccessKeysToReview", []):
        age = k.get("age_days")
        detail = f"key {k.get('key')}, {age} days old" if age is not None else f"key {k.get('key')}, age unknown"
        rows.append(Affected(str(k.get("user")), "global", detail))
    return rows


def _password_policy(data):
    findings = _iam(data)
    if findings is None:
        return None
    return [] if findings.get("PasswordPolicySet") else [Affected("account", "global", "no password policy")]


def _analyzer_coverage(data):
    def getter(region, region_data):
        analyzers = _security(region_data).get("AccessAnalyzers")
        if analyzers is None:
            return None
        active = [a for a in analyzers if (a.get("status") or "ACTIVE") == "ACTIVE"]
        return [] if active else [Affected(region, region, "no analyzer")]

    return _per_region(data, getter)


def _analyzer_findings(data):
    def getter(region, region_data):
        sec = _security(region_data)
        if "AccessAnalyzerFindings" not in sec:
            return None
        if sec.get("AccessAnalyzers") == []:
            return _NOT_APPLICABLE  # no analyzer: zero findings proves nothing
        return [
            Affected(
                str(f.get("resource") or f.get("id") or "?"),
                region,
                f"{f.get('findingType', 'ExternalAccess')} on {f.get('resourceType', '?')}",
            )
            for f in sec["AccessAnalyzerFindings"]
        ]

    return _per_region(data, getter)


def _default_sgs(data):
    return _per_region(
        data,
        _list_items(
            ("DefaultSecurityGroupsWithRules",),
            "GroupId",
            lambda sg: f"{sg.get('VpcId')}: {sg.get('IngressRules')} inbound, {sg.get('EgressRules')} outbound rule(s)",
        ),
    )


def _imds(data):
    return _per_region(
        data,
        _list_items(("Compute", "InstancesAllowingImdsv1"), "InstanceId", lambda i: (i.get("State") or {}).get("Name", "")),
    )


def _lambda_urls(data):
    def getter(region, region_data):
        sec = _security(region_data)
        if "LambdaUrlsWithoutAuth" not in sec:
            return None
        return [Affected(str(f.get("FunctionName")), region, "auth type NONE") for f in sec["LambdaUrlsWithoutAuth"]]

    return _per_region(data, getter)


def _plaintext_listeners(data):
    return _per_region(
        data,
        _list_items(
            ("Compute", "PlaintextListeners"),
            "LoadBalancerName",
            lambda p: f"{p.get('Protocol')} on port {p.get('Port')}",
        ),
    )


def _expiring_certs(data):
    return _per_region(
        data,
        _list_items(("Compute", "ExpiringCertificates"), "DomainName", lambda c: f"expires {c.get('NotAfter')}"),
    )


def _account_bpa(data):
    g = _global(data)
    if "AccountPublicAccessBlock" not in g:
        return None
    bpa = g["AccountPublicAccessBlock"]
    if bpa is None:
        return [Affected("account", "global", "not configured")]
    missing = [k for k in BPA_SETTINGS if not bpa.get(k)]
    return [Affected("account", "global", "off: " + ", ".join(missing))] if missing else []


def account_bpa_fully_on(data) -> bool:
    bpa = _global(data).get("AccountPublicAccessBlock")
    return bool(bpa) and all(bpa.get(k) for k in BPA_SETTINGS)


def _data_stores(data) -> dict | None:
    return _global(data).get("DataStores")


def _buckets_not_read(data, setting: str) -> list[str]:
    """Buckets whose `setting` the scan was denied (a bucket policy, or a
    missing s3:Get* permission)."""
    ds = _data_stores(data) or {}
    return [str(b.get("Name")) for b in ds.get("BucketsNotRead") or [] if setting in (b.get("Settings") or [])]


def _public_buckets(data):
    ds = _data_stores(data)
    if ds is None or "PubliclyAccessibleBuckets" not in ds:
        return None
    affected = [Affected(str(b.get("Name")), "global", "public access not fully blocked") for b in ds["PubliclyAccessibleBuckets"]]
    return affected or (None if _buckets_not_read(data, "PublicAccessBlock") else [])


def _unencrypted_buckets(data):
    ds = _data_stores(data)
    if ds is None or "UnencryptedBuckets" not in ds:
        return None
    affected = [Affected(str(b.get("Name")), "global", "no default encryption") for b in ds["UnencryptedBuckets"]]
    return affected or (None if _buckets_not_read(data, "Encryption") else [])


def _public_ebs_snapshots(data):
    def getter(region, region_data):
        sec = _security(region_data)
        if "PublicEbsSnapshots" not in sec:
            return None
        return [Affected(str(s.get("SnapshotId")), region, f"of volume {s.get('VolumeId')}") for s in sec["PublicEbsSnapshots"]]

    return _per_region(data, getter)


def _public_rds_snapshots(data):
    return _per_region(
        data, _list_items(("PublicRdsSnapshots",), "DBSnapshotIdentifier", lambda s: s.get("Engine") or "")
    )


def _public_rds(data):
    return _per_region(
        data,
        _list_items(("RdsExposure", "PubliclyAccessible"), "DBInstanceIdentifier", lambda i: i.get("Engine") or ""),
    )


def _unencrypted_rds(data):
    return _per_region(
        data, _list_items(("RdsExposure", "Unencrypted"), "DBInstanceIdentifier", lambda i: i.get("Engine") or "")
    )


def _ebs_default_encryption(data):
    def getter(region, region_data):
        sec = _security(region_data)
        if sec.get("EbsEncryptionByDefault") is None:
            return None
        return [] if sec["EbsEncryptionByDefault"] else [Affected(region, region, "off")]

    return _per_region(data, getter)


def _unencrypted_volumes(data):
    def getter(region, region_data):
        sec = _security(region_data)
        if "UnencryptedEbsVolumes" not in sec:
            return None
        return [
            Affected(str(v.get("VolumeId")), region, f"{v.get('State', '?')}, {v.get('SizeGiB', '?')} GiB")
            for v in sec["UnencryptedEbsVolumes"]
        ]

    return _per_region(data, getter)


def _kms_rotation(data):
    def getter(region, region_data):
        sec = _security(region_data)
        if "KmsKeysWithoutRotation" not in sec:
            return None
        return [Affected(str(k.get("KeyId")), region, k.get("Description") or "") for k in sec["KmsKeysWithoutRotation"]]

    return _per_region(data, getter)


# ----------------------------------------------------------------- catalog
CATALOG: list[tuple[Check, object]] = [
    # Detection and logging -- SEC04
    (Check("guardduty-enabled", "GuardDuty is enabled in every scanned region", DETECTION, "HIGH",
           "Enable GuardDuty in each listed region, or org-wide from the delegated administrator",
           "Low", "GuardDuty.1", question="SEC04", finding="GuardDuty is off in some scanned regions"), _guardduty),
    (Check("config-recording", "The AWS Config recorder is recording in every scanned region", DETECTION, "CRITICAL",
           "Start the AWS Config recorder in each listed region; Security Hub controls need its data",
           "Low", "Config.1", exact=False, question="SEC04", finding="The AWS Config recorder isn't recording in some regions"), _config),
    (Check("cloudtrail-multi-region", "A multi-region CloudTrail trail is logging", DETECTION, "HIGH",
           "Create a multi-region (or organization) trail that records management events, and confirm it is logging",
           "Low", "CloudTrail.1", exact=False, question="SEC04", finding="No multi-region CloudTrail trail is logging"), _cloudtrail),
    (Check("inspector-enabled", "Amazon Inspector is active in every scanned region", DETECTION, "HIGH",
           "Activate Amazon Inspector (EC2 scanning at minimum) in each listed region",
           "Low", "Inspector.1", exact=False, question="SEC06", finding="Amazon Inspector is off in some regions"), _inspector),
    (Check("securityhub-enabled", "Security Hub is enabled in every scanned region", DETECTION, "MEDIUM",
           "Enable Security Hub with the AWS Foundational Security Best Practices standard in each listed region",
           "Low", question="SEC04", finding="Security Hub is off in some regions"), _securityhub),
    (Check("macie-enabled", "Amazon Macie is enabled in every scanned region", DETECTION, "MEDIUM",
           "Enable Macie where the account stores sensitive data in S3",
           "Low", "Macie.1", question="SEC07", finding="Amazon Macie is off in some regions"), _macie),
    (Check("cloudtrail-log-validation", "Every trail validates its log files", DETECTION, "LOW",
           "Turn on log file validation for each listed trail",
           "Low", "CloudTrail.4", question="SEC04", finding="Some trails don't validate their log files"), _cloudtrail_validation),
    # Identity and access -- SEC02, SEC03
    (Check("root-access-key", "The root user has no access key", IDENTITY, "CRITICAL",
           "Delete the root user's access keys; use IAM roles for programmatic access",
           "Low", "IAM.4", question="SEC02", finding="The root user has an active access key"), _root_risk(ROOT_KEY_RISK)),
    (Check("root-mfa", "The root user has MFA", IDENTITY, "CRITICAL",
           "Add MFA (hardware key or passkey) to the root user",
           "Low", "IAM.9", question="SEC02", finding="The root user has no MFA"), _root_risk(ROOT_MFA_RISK)),
    (Check("console-mfa", "Every IAM user with a console password has MFA", IDENTITY, "MEDIUM",
           "Require MFA for each listed user, or move console access to IAM Identity Center",
           "Medium", "IAM.5", question="SEC02", finding="Console users without MFA"), _console_mfa),
    (Check("access-key-age", "No active access key is older than 90 days", IDENTITY, "MEDIUM",
           "Rotate or delete the listed access keys; prefer roles and short-lived credentials",
           "Medium", "IAM.3", question="SEC02", finding="Access keys older than 90 days"), _key_age),
    (Check("password-policy", "An account password policy is set", IDENTITY, "MEDIUM",
           "Set an account password policy (length 14+, all character classes, reuse prevention)",
           "Low", "IAM.7", exact=False, question="SEC02", finding="No account password policy"), _password_policy),
    (Check("access-analyzer-findings", "IAM Access Analyzer has no active findings", IDENTITY, "MEDIUM",
           "Review each finding: archive intended access, remove the rest",
           "Medium", question="SEC03", finding="IAM Access Analyzer reports active findings"), _analyzer_findings),
    (Check("access-analyzer-enabled", "An IAM Access Analyzer analyzer exists in every scanned region", IDENTITY, "LOW",
           "Create an account analyzer in each listed region, or confirm an organization analyzer covers this account",
           "Low", question="SEC03", finding="Regions without an IAM Access Analyzer analyzer"), _analyzer_coverage),
    # Network exposure -- SEC05, SEC06, SEC09
    (Check("sg-high-risk-ports", "No security group opens a high-risk port to the internet", NETWORK, "CRITICAL",
           "Restrict these rules to known address ranges or security groups; reach hosts with Session Manager instead",
           "Low", "EC2.19", question="SEC05", finding="High-risk ports open to the internet"), lambda d: _per_region(d, _high_risk_rules)),
    (Check("sg-unauthorized-ports", "Internet-open security group rules allow only ports 80 and 443", NETWORK, "HIGH",
           "Limit internet-open rules to the ports the workload serves",
           "Low", "EC2.18", question="SEC05", finding="Internet-open rules on ports other than 80 and 443"), lambda d: _per_region(d, _unauthorized_rules)),
    (Check("default-sg-closed", "Default security groups allow no traffic", NETWORK, "HIGH",
           "Remove every inbound and outbound rule from each listed default security group",
           "Low", "EC2.2", question="SEC05", finding="Default security groups allow traffic"), _default_sgs),
    (Check("imdsv2-required", "Every instance requires IMDSv2", NETWORK, "HIGH",
           "Set HttpTokens=required on the listed instances after confirming their SDKs support IMDSv2",
           "Medium", "EC2.8", question="SEC06", finding="Instances still accept IMDSv1"), _imds),
    (Check("lambda-url-auth", "No Lambda function URL accepts unauthenticated requests", NETWORK, "HIGH",
           "Switch the function URL to AWS_IAM auth, or put an authenticating service in front of it",
           "Medium", "Lambda.1", exact=False, question="SEC05", finding="Lambda function URLs without authentication"), _lambda_urls),
    (Check("listener-tls", "Load balancer listeners use TLS or redirect to HTTPS", NETWORK, "MEDIUM",
           "Add an HTTPS/TLS listener and redirect or close each plaintext one",
           "Medium", "ELB.1", exact=False, question="SEC09", finding="Load balancer listeners without TLS"), _plaintext_listeners),
    (Check("acm-expiry", "No ACM certificate expires within 30 days", NETWORK, "MEDIUM",
           "Renew or re-import the listed certificates; for managed ones, check the DNS validation records",
           "Low", "ACM.1", exact=False, question="SEC09", finding="ACM certificates expired or expiring within 30 days"), _expiring_certs),
    # Data protection -- SEC07, SEC08
    (Check("ebs-snapshot-public", "No EBS snapshot is publicly restorable", DATA, "CRITICAL",
           "Remove the public restore permission from each listed snapshot",
           "Low", "EC2.1", question="SEC08", finding="Publicly restorable EBS snapshots"), _public_ebs_snapshots),
    (Check("rds-snapshot-public", "No RDS snapshot is shared publicly", DATA, "CRITICAL",
           "Remove the public restore attribute from each listed DB or cluster snapshot",
           "Low", "RDS.1", question="SEC08", finding="Publicly shared RDS snapshots"), _public_rds_snapshots),
    (Check("rds-public", "No RDS instance is publicly accessible", DATA, "CRITICAL",
           "Set PubliclyAccessible to false and keep the instances in private subnets",
           "Medium", "RDS.2", question="SEC05", finding="Publicly accessible RDS instances"), _public_rds),
    (Check("s3-bucket-public", "Every S3 bucket blocks public access", DATA, "HIGH",
           "Turn on all four Block Public Access settings on each listed bucket that doesn't serve public content",
           "Low", "S3.8", question="SEC08", finding="Buckets that don't block public access"), _public_buckets),
    (Check("s3-account-bpa", "Account-level S3 Block Public Access is fully on", DATA, "MEDIUM",
           "Turn on all four account-level Block Public Access settings",
           "Low", "S3.1", question="SEC08", finding="Account-level S3 Block Public Access is incomplete"), _account_bpa),
    (Check("ebs-default-encryption", "EBS encryption by default is on in every scanned region", DATA, "MEDIUM",
           "Turn on EBS encryption by default in each listed region",
           "Low", "EC2.7", question="SEC08", finding="EBS encryption by default is off in some regions"), _ebs_default_encryption),
    (Check("ebs-volume-encryption", "Every EBS volume is encrypted", DATA, "MEDIUM",
           "Copy a snapshot of each listed volume with encryption on, then swap in a volume restored from it",
           "High", "EC2.3", exact=False, question="SEC08", finding="Unencrypted EBS volumes"), _unencrypted_volumes),
    (Check("rds-encryption", "Every RDS instance encrypts its storage", DATA, "MEDIUM",
           "Restore each listed instance from an encrypted copy of its snapshot",
           "High", "RDS.3", question="SEC08", finding="RDS instances with unencrypted storage"), _unencrypted_rds),
    (Check("kms-rotation", "Customer-managed KMS keys rotate automatically", DATA, "MEDIUM",
           "Turn on automatic rotation for each listed key",
           "Low", "KMS.4", question="SEC08", finding="KMS keys without automatic rotation"), _kms_rotation),
    (Check("s3-default-encryption", "Every S3 bucket has default encryption", DATA, "LOW",
           "Set default encryption (SSE-S3 or SSE-KMS) on each listed bucket",
           "Low", question="SEC08", finding="Buckets without default encryption"), _unencrypted_buckets),
]

CHECKS_BY_ID = {check.id: check for check, _ in CATALOG}


_BUCKET_CHECKS = {"s3-bucket-public": "PublicAccessBlock", "s3-default-encryption": "Encryption"}


def evaluate_checks(data: dict) -> list[CheckResult]:
    """Every check, against the evidence the scan could read. A check whose
    evidence was denied is NO DATA with a note saying so; one that fails on
    the part that was read stays a FAIL, with a note that it is partial."""
    readable = readable_evidence(data)
    results = evaluate(CATALOG, readable)
    if readable is not data:
        for r, unscrubbed in zip(results, evaluate(CATALOG, data), strict=True):
            if r.status == NO_DATA and unscrubbed.status != NO_DATA:
                r.note = DENIED_NOTE
            elif r.failed and len(r.affected) < len(unscrubbed.affected):
                r.note = PARTIAL_NOTE
    for r in results:
        unread = _buckets_not_read(data, _BUCKET_CHECKS.get(r.check.id, ""))
        if unread:
            r.note = (DENIED_NOTE if r.status == NO_DATA else PARTIAL_NOTE) + f" Buckets not read: {len(unread)}."
    data = readable
    if account_bpa_fully_on(data):
        for r in results:
            if r.check.id == "s3-bucket-public" and r.failed:
                r.note = (r.note + " " if r.note else "") + (
                    "Account-level Block Public Access is fully on, which overrides these bucket "
                    "settings: the buckets can't be made public until it is turned off."
                )
    return results


# ------------------------------------------------------------ attack paths
def _instance_label(instance: dict) -> str:
    name = next((t.get("Value") for t in instance.get("Tags") or [] if t.get("Key") == "Name"), None)
    return f"{instance.get('InstanceId')} ({name})" if name else str(instance.get("InstanceId"))


def _public_instances(region_data: dict) -> list[dict]:
    instances = (region_data.get("Compute") or {}).get("Instances") or []
    return [
        i for i in instances
        if i.get("PublicIpAddress") and (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down", "stopped")
    ]


def _open_rules_by_group(region_data: dict) -> dict[str, list[dict]]:
    by_group: dict[str, list[dict]] = {}
    for rule in region_data.get("WideOpenSecurityGroups") or []:
        by_group.setdefault(rule.get("GroupId"), []).append(rule)
    return by_group


def _exposed_imdsv1(data: dict) -> list[Affected]:
    affected = []
    for region, region_data in _regions(data).items():
        imds_ids = {i.get("InstanceId") for i in (region_data.get("Compute") or {}).get("InstancesAllowingImdsv1") or []}
        open_rules = _open_rules_by_group(region_data)
        for instance in _public_instances(region_data):
            if instance.get("InstanceId") not in imds_ids:
                continue
            groups = [g.get("GroupId") for g in instance.get("SecurityGroups") or [] if g.get("GroupId") in open_rules]
            if groups:
                rules = "; ".join(_rule_text(r) for g in groups for r in open_rules[g])
                affected.append(
                    Affected(_instance_label(instance), region, f"public IP {instance['PublicIpAddress']}, {rules}")
                )
    return affected


def _public_high_risk_ports(data: dict) -> list[Affected]:
    affected = []
    for region, region_data in _regions(data).items():
        open_rules = _open_rules_by_group(region_data)
        for instance in _public_instances(region_data):
            exposed = []
            for g in instance.get("SecurityGroups") or []:
                for rule in open_rules.get(g.get("GroupId"), []):
                    ports = high_risk_ports_in(rule)
                    if ports:
                        shown = ", ".join(str(p) for p in ports[:4]) + (" and more" if len(ports) > 4 else "")
                        exposed.append(f"{g.get('GroupId')} opens {shown}")
            if exposed:
                affected.append(
                    Affected(_instance_label(instance), region, f"public IP {instance['PublicIpAddress']}; " + "; ".join(exposed))
                )
    return affected


def _public_unencrypted_rds(data: dict) -> list[Affected]:
    affected = []
    for region, region_data in _regions(data).items():
        exposure = region_data.get("RdsExposure") or {}
        unencrypted = {i.get("DBInstanceIdentifier") for i in exposure.get("Unencrypted") or []}
        for i in exposure.get("PubliclyAccessible") or []:
            if i.get("DBInstanceIdentifier") in unencrypted:
                affected.append(Affected(str(i.get("DBInstanceIdentifier")), region, i.get("Engine") or ""))
    return affected


def _region_exposures(region_data: dict) -> list[str]:
    sec = _security(region_data)
    items = []
    rules = region_data.get("WideOpenSecurityGroups") or []
    if rules:
        items.append(f"{len(rules)} internet-open security group rule(s)")
    public_db = (region_data.get("RdsExposure") or {}).get("PubliclyAccessible") or []
    if public_db:
        items.append(f"{len(public_db)} public RDS instance(s)")
    urls = sec.get("LambdaUrlsWithoutAuth") or []
    if urls:
        items.append(f"{len(urls)} unauthenticated Lambda URL(s)")
    snaps = len(sec.get("PublicEbsSnapshots") or []) + len(region_data.get("PublicRdsSnapshots") or [])
    if snaps:
        items.append(f"{snaps} public snapshot(s)")
    return items


def _exposure_without_detection(data: dict) -> list[Affected]:
    affected = []
    for region, region_data in _regions(data).items():
        gd = _security(region_data).get("GuardDuty")
        if gd is None or gd.get("Enabled"):
            continue
        exposures = _region_exposures(region_data)
        if exposures:
            affected.append(Affected(region, region, "GuardDuty off; " + ", ".join(exposures)))
    return affected


def _active_threat_findings(data: dict) -> list[dict]:
    found = []
    for region, region_data in _regions(data).items():
        for f in _security(region_data).get("GuardDutyFindings") or []:
            if float(f.get("Severity", 0) or 0) >= 7.0:
                found.append({**f, "_Region": region})
    return found


def _threats_without_trail(data: dict) -> list[Affected]:
    trail = _cloudtrail(data)
    if not trail:  # None (no evidence) or [] (a logging multi-region trail exists)
        return []
    threats = _active_threat_findings(data)
    if not threats:
        return []
    regions = sorted({f["_Region"] for f in threats})
    return [Affected("account", "global", f"{len(threats)} high/critical GuardDuty finding(s) in {', '.join(regions)}")]


def _buckets_without_backstop(data: dict) -> list[Affected]:
    if account_bpa_fully_on(data):
        return []
    buckets = _public_buckets(data) or []
    return [Affected(b.resource, "global", "bucket and account Block Public Access both incomplete") for b in buckets]


ATTACK_PATHS = (
    (
        "exposed-imdsv1-instance",
        "Internet-reachable instance still accepts IMDSv1",
        "CRITICAL",
        "A server-side request forgery bug on a host the internet can reach can read the instance "
        "role's credentials from IMDSv1, which needs no session token.",
        "Require IMDSv2 on these instances first, then narrow the open security group rules",
        ("imdsv2-required", "sg-unauthorized-ports"),
        "Medium",
        _exposed_imdsv1,
    ),
    (
        "public-instance-high-risk-port",
        "Running public instance has an administration or database port open to the internet",
        "CRITICAL",
        "The port is reachable from any address and the instance answers on a public IP, so it is "
        "exposed to scanning and credential attacks today, not only in principle.",
        "Close the port to 0.0.0.0/0 and ::/0; use Session Manager or a VPN for administration",
        ("sg-high-risk-ports",),
        "Low",
        _public_high_risk_ports,
    ),
    (
        "public-unencrypted-database",
        "Publicly accessible RDS instance with unencrypted storage",
        "CRITICAL",
        "The database endpoint resolves to a public address and its storage, snapshots, and "
        "replicas are unencrypted.",
        "Make the instance private now; then migrate it to an encrypted copy",
        ("rds-public", "rds-encryption"),
        "High",
        _public_unencrypted_rds,
    ),
    (
        "exposure-without-detection",
        "Internet-exposed resources in a region without GuardDuty",
        "HIGH",
        "An attack on these resources would raise no GuardDuty alert, because threat detection is "
        "off in the same region.",
        "Enable GuardDuty in these regions before (or while) closing the exposures",
        ("guardduty-enabled", "sg-unauthorized-ports", "rds-public", "lambda-url-auth"),
        "Low",
        _exposure_without_detection,
    ),
    (
        "threats-without-audit-trail",
        "Active threat findings with no multi-region audit trail",
        "HIGH",
        "GuardDuty reports high or critical findings, but without a logging multi-region trail "
        "there is no API history to investigate them with.",
        "Turn on a multi-region trail now so the next events are recorded, then investigate the findings",
        ("cloudtrail-multi-region",),
        "Low",
        _threats_without_trail,
    ),
    (
        "public-bucket-without-backstop",
        "Buckets open to public access with no account-level backstop",
        "HIGH",
        "Neither the bucket nor the account blocks public access, so one policy or ACL change "
        "makes the data public.",
        "Turn on account-level Block Public Access unless a bucket must serve public content",
        ("s3-bucket-public", "s3-account-bpa"),
        "Low",
        _buckets_without_backstop,
    ),
)


def attack_paths(data: dict) -> list[AttackPath]:
    data = readable_evidence(data)
    paths = []
    for path_id, title, severity, why, fix, builds_on, effort, finder in ATTACK_PATHS:
        affected = finder(data)
        if affected:
            paths.append(AttackPath(path_id, title, severity, why, fix, affected, builds_on, effort))
    return paths


# ------------------------------------------------------------------ threats
def threats(data: dict, guardduty_label) -> list[Threat]:
    """GuardDuty high/critical findings grouped by finding type, plus the
    open Security Hub critical/high findings as one triage item."""
    data = readable_evidence(data)
    by_type: dict[str, list[dict]] = {}
    for f in _active_threat_findings(data):
        by_type.setdefault(f.get("Type", "?"), []).append(f)
    out = []
    for finding_type, items in by_type.items():
        worst = max(float(f.get("Severity", 0) or 0) for f in items)
        affected = [
            Affected(
                str(((f.get("Resource") or {}).get("ResourceType")) or "resource"),
                f["_Region"],
                str(f.get("Title") or ""),
            )
            for f in items
        ]
        out.append(
            Threat(
                title=f"GuardDuty: {finding_type}",
                severity=guardduty_label(worst),
                action=f"Investigate the {finding_type} finding(s) and contain the affected resource",
                affected=affected,
                reference="GuardDuty",
            )
        )
    sh = []
    for region, region_data in _regions(data).items():
        for f in _security(region_data).get("SecurityHubFindings") or []:
            label = (f.get("Severity") or {}).get("Label")
            if label in ("CRITICAL", "HIGH"):
                sh.append(Affected(str(((f.get("Resources") or [{}])[0]).get("Id", "?")), region, str(f.get("Title", ""))))
    if sh:
        has_critical = any(
            (f.get("Severity") or {}).get("Label") == "CRITICAL"
            for rd in _regions(data).values()
            for f in _security(rd).get("SecurityHubFindings") or []
        )
        out.append(
            Threat(
                title=f"{len(sh)} open Security Hub finding(s) rated high or critical",
                severity="CRITICAL" if has_critical else "HIGH",
                action="Triage the open Security Hub findings listed in this report",
                affected=sh,
                reference="Security Hub",
            )
        )
    return out


def detection_coverage(data: dict) -> tuple[int, int]:
    """(services on, services checked) across GuardDuty, Security Hub,
    Inspector, Macie, and the Config recorder in every scanned region."""
    on = total = 0
    for region_data in _regions(readable_evidence(data)).values():
        sec = _security(region_data)
        for key in ("GuardDuty", "SecurityHub", "Inspector2", "Macie"):
            if sec.get(key) is not None:
                total += 1
                on += bool(sec[key].get("Enabled"))
        if sec.get("ConfigRecorder") is not None:
            total += 1
            on += bool(sec["ConfigRecorder"].get("Recording"))
    return on, total


def analyze(data: dict, guardduty_label) -> dict:
    """Everything the report and the JSON evidence need, in one call."""
    results = evaluate_checks(data)
    paths = attack_paths(data)
    found_threats = threats(data, guardduty_label)
    return {
        "results": results,
        "paths": paths,
        "threats": found_threats,
        "actions": prioritize(results, paths, found_threats, limit=10, domain_order=PRIORITY_DOMAINS),
        "score": score(results),
    }
