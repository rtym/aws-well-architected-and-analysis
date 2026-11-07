"""The security check catalog, attack-path correlations, and threat triage."""
import copy

import pytest

from shared.analysis import checks as engine
from shared.analysis import security_checks as sc
from shared.awslib.collectors.security import guardduty_severity_label


def clean_bundle(**region_overrides) -> dict:
    """A one-region evidence bundle in which every check passes."""
    region = {
        "Security": {
            "GuardDuty": {"Enabled": True},
            "SecurityHub": {"Enabled": True},
            "Inspector2": {"Enabled": True},
            "Macie": {"Enabled": True},
            "ConfigRecorder": {"Recording": True},
            "GuardDutyFindings": [],
            "SecurityHubFindings": [],
            "AccessAnalyzers": [{"name": "acct", "status": "ACTIVE"}],
            "AccessAnalyzerFindings": [],
            "EbsEncryptionByDefault": True,
            "UnencryptedEbsVolumes": [],
            "PublicEbsSnapshots": [],
            "KmsKeysWithoutRotation": [],
            "LambdaUrlsWithoutAuth": [],
        },
        "WideOpenSecurityGroups": [],
        "DefaultSecurityGroupsWithRules": [],
        "RdsExposure": {"PubliclyAccessible": [], "Unencrypted": []},
        "PublicRdsSnapshots": [],
        "Compute": {"Instances": [], "InstancesAllowingImdsv1": [], "PlaintextListeners": [], "ExpiringCertificates": []},
    }
    for key, value in region_overrides.items():
        if key in region["Security"]:
            region["Security"][key] = value
        else:
            region[key] = value
    return {
        "Regions": {"us-east-1": region},
        "Global": {
            "IamFindings": {"ConsoleUsersWithoutMfa": [], "AccessKeysToReview": [], "RootAccountRisks": [], "PasswordPolicySet": True},
            "DataStores": {"PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []},
            "AccountPublicAccessBlock": {k: True for k in sc.BPA_SETTINGS},
            "CloudTrail": {
                "Trails": [{"Name": "t", "LogFileValidationEnabled": True}],
                "HasMultiRegionTrail": True,
                "HasLoggingTrail": True,
                "HasLoggingMultiRegionTrail": True,
                "HasLogFileValidation": True,
            },
        },
    }


def _status(data: dict) -> dict[str, str]:
    return {r.check.id: r.status for r in sc.evaluate_checks(data)}


def _result(data: dict, check_id: str):
    return next(r for r in sc.evaluate_checks(data) if r.check.id == check_id)


# ------------------------------------------------------------------ catalog
def test_catalog_ids_are_unique_and_every_check_is_fully_described():
    ids = [c.id for c, _ in sc.CATALOG]
    assert len(ids) == len(set(ids))
    for check, _ in sc.CATALOG:
        assert check.domain in sc.DOMAINS
        assert check.finding and check.remediation and check.question.startswith("SEC")
        assert not check.remediation.endswith(".")  # rendered inside sentences


def test_clean_account_passes_every_check():
    statuses = _status(clean_bundle())
    assert set(statuses.values()) == {engine.PASS}
    assert engine.score(sc.evaluate_checks(clean_bundle())).score == 100


def test_empty_evidence_is_no_data_not_pass():
    """Evidence from an older plugin version (or nothing at all) must not
    score as a clean account."""
    assert set(_status({}).values()) == {engine.NO_DATA}
    assert engine.score(sc.evaluate_checks({})).score is None


@pytest.mark.parametrize(
    "check_id, mutate",
    [
        ("guardduty-enabled", lambda d: d["Regions"]["us-east-1"]["Security"].update(GuardDuty={"Enabled": False})),
        ("securityhub-enabled", lambda d: d["Regions"]["us-east-1"]["Security"].update(SecurityHub={"Enabled": False})),
        ("inspector-enabled", lambda d: d["Regions"]["us-east-1"]["Security"].update(Inspector2={"Enabled": False})),
        ("macie-enabled", lambda d: d["Regions"]["us-east-1"]["Security"].update(Macie={"Enabled": False})),
        ("config-recording", lambda d: d["Regions"]["us-east-1"]["Security"].update(ConfigRecorder={"Recording": False})),
        ("cloudtrail-multi-region", lambda d: d["Global"]["CloudTrail"].update(HasLoggingMultiRegionTrail=False)),
        ("cloudtrail-log-validation", lambda d: d["Global"]["CloudTrail"]["Trails"][0].update(LogFileValidationEnabled=False)),
        ("root-access-key", lambda d: d["Global"]["IamFindings"]["RootAccountRisks"].append(sc.ROOT_KEY_RISK)),
        ("root-mfa", lambda d: d["Global"]["IamFindings"]["RootAccountRisks"].append(sc.ROOT_MFA_RISK)),
        ("console-mfa", lambda d: d["Global"]["IamFindings"]["ConsoleUsersWithoutMfa"].append("alice")),
        ("access-key-age", lambda d: d["Global"]["IamFindings"]["AccessKeysToReview"].append({"user": "ci", "key": "1", "age_days": 120})),
        ("password-policy", lambda d: d["Global"]["IamFindings"].update(PasswordPolicySet=False)),
        ("access-analyzer-findings", lambda d: d["Regions"]["us-east-1"]["Security"]["AccessAnalyzerFindings"].append({"resource": "arn:aws:s3:::b"})),
        ("access-analyzer-enabled", lambda d: d["Regions"]["us-east-1"]["Security"].update(AccessAnalyzers=[])),
        ("default-sg-closed", lambda d: d["Regions"]["us-east-1"]["DefaultSecurityGroupsWithRules"].append({"GroupId": "sg-d", "VpcId": "vpc-1"})),
        ("imdsv2-required", lambda d: d["Regions"]["us-east-1"]["Compute"]["InstancesAllowingImdsv1"].append({"InstanceId": "i-1"})),
        ("lambda-url-auth", lambda d: d["Regions"]["us-east-1"]["Security"]["LambdaUrlsWithoutAuth"].append({"FunctionName": "f"})),
        ("listener-tls", lambda d: d["Regions"]["us-east-1"]["Compute"]["PlaintextListeners"].append({"LoadBalancerName": "lb", "Protocol": "HTTP", "Port": 80})),
        ("acm-expiry", lambda d: d["Regions"]["us-east-1"]["Compute"]["ExpiringCertificates"].append({"DomainName": "x.example"})),
        ("ebs-snapshot-public", lambda d: d["Regions"]["us-east-1"]["Security"]["PublicEbsSnapshots"].append({"SnapshotId": "snap-1"})),
        ("rds-snapshot-public", lambda d: d["Regions"]["us-east-1"]["PublicRdsSnapshots"].append({"DBSnapshotIdentifier": "s"})),
        ("rds-public", lambda d: d["Regions"]["us-east-1"]["RdsExposure"]["PubliclyAccessible"].append({"DBInstanceIdentifier": "db"})),
        ("rds-encryption", lambda d: d["Regions"]["us-east-1"]["RdsExposure"]["Unencrypted"].append({"DBInstanceIdentifier": "db"})),
        ("s3-bucket-public", lambda d: d["Global"]["DataStores"]["PubliclyAccessibleBuckets"].append({"Name": "b"})),
        ("s3-default-encryption", lambda d: d["Global"]["DataStores"]["UnencryptedBuckets"].append({"Name": "b"})),
        ("s3-account-bpa", lambda d: d["Global"]["AccountPublicAccessBlock"].update(BlockPublicPolicy=False)),
        ("ebs-default-encryption", lambda d: d["Regions"]["us-east-1"]["Security"].update(EbsEncryptionByDefault=False)),
        ("ebs-volume-encryption", lambda d: d["Regions"]["us-east-1"]["Security"]["UnencryptedEbsVolumes"].append({"VolumeId": "vol-1"})),
        ("kms-rotation", lambda d: d["Regions"]["us-east-1"]["Security"]["KmsKeysWithoutRotation"].append({"KeyId": "k"})),
    ],
)
def test_each_check_fails_on_its_own_evidence(check_id, mutate):
    data = clean_bundle()
    mutate(data)
    statuses = _status(data)
    assert statuses[check_id] == engine.FAIL
    # ...and only the checks that read that evidence fail with it.
    assert sum(1 for s in statuses.values() if s == engine.FAIL) <= 2


def test_account_bpa_not_configured_fails_and_missing_key_is_no_data():
    data = clean_bundle()
    data["Global"]["AccountPublicAccessBlock"] = None
    assert _result(data, "s3-account-bpa").affected[0].detail == "not configured"
    del data["Global"]["AccountPublicAccessBlock"]
    assert _status(data)["s3-account-bpa"] == engine.NO_DATA


def test_cloudtrail_falls_back_for_evidence_from_before_1_4_1():
    data = clean_bundle()
    del data["Global"]["CloudTrail"]["HasLoggingMultiRegionTrail"]
    assert _status(data)["cloudtrail-multi-region"] == engine.PASS
    data["Global"]["CloudTrail"]["HasLoggingTrail"] = False
    assert _status(data)["cloudtrail-multi-region"] == engine.FAIL


def test_log_validation_without_trails_is_no_data():
    data = clean_bundle()
    data["Global"]["CloudTrail"]["Trails"] = []
    assert _status(data)["cloudtrail-log-validation"] == engine.NO_DATA


def test_access_analyzer_findings_are_no_data_without_an_analyzer():
    """Zero findings from zero analyzers proves nothing."""
    data = clean_bundle(AccessAnalyzers=[])
    statuses = _status(data)
    assert statuses["access-analyzer-findings"] == engine.NO_DATA
    assert statuses["access-analyzer-enabled"] == engine.FAIL


def test_unknown_ebs_default_encryption_is_no_data():
    assert _status(clean_bundle(EbsEncryptionByDefault=None))["ebs-default-encryption"] == engine.NO_DATA


def test_access_key_with_unknown_age_still_reads_cleanly():
    data = clean_bundle()
    data["Global"]["IamFindings"]["AccessKeysToReview"] = [{"user": "u", "key": "2", "age_days": None}]
    assert _result(data, "access-key-age").affected[0].detail == "key 2, age unknown"


def test_public_bucket_check_notes_the_account_level_backstop():
    data = clean_bundle()
    data["Global"]["DataStores"]["PubliclyAccessibleBuckets"] = [{"Name": "b"}]
    result = _result(data, "s3-bucket-public")
    assert result.failed and "overrides these bucket settings" in result.note
    data["Global"]["AccountPublicAccessBlock"]["IgnorePublicAcls"] = False
    assert _result(data, "s3-bucket-public").note == ""


def test_a_check_fails_when_any_region_fails():
    data = clean_bundle()
    data["Regions"]["eu-west-1"] = copy.deepcopy(data["Regions"]["us-east-1"])
    data["Regions"]["eu-west-1"]["Security"]["GuardDuty"] = {"Enabled": False}
    result = _result(data, "guardduty-enabled")
    assert result.failed and [a.region for a in result.affected] == ["eu-west-1"]


def test_region_without_a_service_status_is_skipped_not_failed():
    data = clean_bundle()
    del data["Regions"]["us-east-1"]["Security"]["Macie"]
    assert _status(data)["macie-enabled"] == engine.NO_DATA


# ------------------------------------------------------------- port logic
@pytest.mark.parametrize(
    "rule, high_risk, unauthorized",
    [
        ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}, [22], True),
        ({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}, [], False),
        ({"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80}, [], False),
        ({"IpProtocol": "tcp", "FromPort": 80, "ToPort": 443}, [110, 135, 143], True),
        ({"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8443}, [], True),
        ({"IpProtocol": "udp", "FromPort": 53, "ToPort": 53}, [], True),
        ({"IpProtocol": "6", "FromPort": 3389, "ToPort": 3389}, [3389], True),
        ({"IpProtocol": "-1"}, list(sc.HIGH_RISK_PORTS), True),
        ({"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1}, [], False),
        ({"IpProtocol": "tcp", "FromPort": None, "ToPort": None}, list(sc.HIGH_RISK_PORTS), True),
    ],
)
def test_port_rules_match_security_hub_ec2_19_and_ec2_18(rule, high_risk, unauthorized):
    assert sc.high_risk_ports_in(rule) == high_risk
    assert sc.opens_unauthorized_port(rule) is unauthorized


def test_open_web_port_fails_neither_port_check():
    data = clean_bundle(WideOpenSecurityGroups=[{"GroupId": "sg-web", "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "OpenRanges": ["0.0.0.0/0"]}])
    statuses = _status(data)
    assert statuses["sg-high-risk-ports"] == statuses["sg-unauthorized-ports"] == engine.PASS


def test_rule_detail_text_names_ports_protocol_and_ranges():
    data = clean_bundle(
        WideOpenSecurityGroups=[
            {"GroupId": "sg-a", "IpProtocol": "tcp", "FromPort": 1000, "ToPort": 2000, "OpenRanges": ["::/0"]},
            {"GroupId": "sg-b", "IpProtocol": "-1", "OpenRanges": ["0.0.0.0/0"]},
        ]
    )
    details = {a.resource: a.detail for a in _result(data, "sg-unauthorized-ports").affected}
    assert details == {"sg-a": "1000-2000/tcp from ::/0", "sg-b": "all traffic from 0.0.0.0/0"}


# ------------------------------------------------------------ attack paths
def _public_instance(**kw):
    instance = {
        "InstanceId": "i-1",
        "PublicIpAddress": "54.0.0.1",
        "State": {"Name": "running"},
        "SecurityGroups": [{"GroupId": "sg-1"}],
        "Tags": [{"Key": "Name", "Value": "bastion"}],
    }
    instance.update(kw)
    return instance


def _paths(data) -> dict:
    return {p.id: p for p in sc.attack_paths(data)}


def test_internet_reachable_imdsv1_instance_is_an_attack_path():
    instance = _public_instance()
    data = clean_bundle(
        WideOpenSecurityGroups=[{"GroupId": "sg-1", "IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8443, "OpenRanges": ["0.0.0.0/0"]}],
        Compute={"Instances": [instance], "InstancesAllowingImdsv1": [instance], "PlaintextListeners": [], "ExpiringCertificates": []},
    )
    path = _paths(data)["exposed-imdsv1-instance"]
    assert path.severity == "CRITICAL"
    (hit,) = path.affected
    assert hit.resource == "i-1 (bastion)"
    assert "54.0.0.1" in hit.detail and "8443/tcp" in hit.detail
    # 8443 isn't a high-risk port, so the port path stays quiet.
    assert "public-instance-high-risk-port" not in _paths(data)


@pytest.mark.parametrize(
    "instance, imds",
    [
        (_public_instance(PublicIpAddress=None), True),  # private
        (_public_instance(State={"Name": "stopped"}), True),  # not running
        (_public_instance(SecurityGroups=[{"GroupId": "sg-closed"}]), True),  # no open rule
        (_public_instance(), False),  # IMDSv2 enforced
    ],
)
def test_imdsv1_attack_path_needs_every_ingredient(instance, imds):
    data = clean_bundle(
        WideOpenSecurityGroups=[{"GroupId": "sg-1", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "OpenRanges": ["0.0.0.0/0"]}],
        Compute={
            "Instances": [instance],
            "InstancesAllowingImdsv1": [instance] if imds else [],
            "PlaintextListeners": [],
            "ExpiringCertificates": [],
        },
    )
    assert "exposed-imdsv1-instance" not in _paths(data)


def test_public_instance_with_high_risk_port_is_an_attack_path():
    many_ports = {"GroupId": "sg-1", "IpProtocol": "-1", "OpenRanges": ["0.0.0.0/0"]}
    data = clean_bundle(
        WideOpenSecurityGroups=[many_ports],
        Compute={"Instances": [_public_instance(Tags=[])], "InstancesAllowingImdsv1": [], "PlaintextListeners": [], "ExpiringCertificates": []},
    )
    (hit,) = _paths(data)["public-instance-high-risk-port"].affected
    assert hit.resource == "i-1"
    assert "sg-1 opens 20, 21, 22, 23 and more" in hit.detail


def test_public_unencrypted_database_is_an_attack_path():
    db = {"DBInstanceIdentifier": "orders", "Engine": "postgres"}
    data = clean_bundle(RdsExposure={"PubliclyAccessible": [db], "Unencrypted": [db, {"DBInstanceIdentifier": "other"}]})
    assert [a.resource for a in _paths(data)["public-unencrypted-database"].affected] == ["orders"]


def test_exposure_in_a_region_without_guardduty_is_an_attack_path():
    data = clean_bundle(
        GuardDuty={"Enabled": False},
        WideOpenSecurityGroups=[{"GroupId": "sg-1", "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "OpenRanges": ["0.0.0.0/0"]}],
        RdsExposure={"PubliclyAccessible": [{"DBInstanceIdentifier": "db"}], "Unencrypted": []},
        LambdaUrlsWithoutAuth=[{"FunctionName": "f"}],
        PublicEbsSnapshots=[{"SnapshotId": "s"}],
        PublicRdsSnapshots=[{"DBSnapshotIdentifier": "r"}],
    )
    (hit,) = _paths(data)["exposure-without-detection"].affected
    assert hit.resource == "us-east-1"
    for fragment in ("1 internet-open security group rule(s)", "1 public RDS instance(s)", "1 unauthenticated Lambda URL(s)", "2 public snapshot(s)"):
        assert fragment in hit.detail
    # GuardDuty off but nothing exposed: no path.
    assert "exposure-without-detection" not in _paths(clean_bundle(GuardDuty={"Enabled": False}))


def test_threats_without_an_audit_trail_is_an_attack_path():
    data = clean_bundle(GuardDutyFindings=[{"Type": "Trojan:EC2/X", "Severity": 8.0}])
    assert "threats-without-audit-trail" not in _paths(data)  # the trail is logging
    data["Global"]["CloudTrail"]["HasLoggingMultiRegionTrail"] = False
    (hit,) = _paths(data)["threats-without-audit-trail"].affected
    assert "1 high/critical GuardDuty finding(s) in us-east-1" == hit.detail
    del data["Global"]["CloudTrail"]
    assert "threats-without-audit-trail" not in _paths(data)  # no evidence, no claim


def test_public_bucket_without_account_backstop_is_an_attack_path():
    data = clean_bundle()
    data["Global"]["DataStores"]["PubliclyAccessibleBuckets"] = [{"Name": "open"}]
    assert "public-bucket-without-backstop" not in _paths(data)
    data["Global"]["AccountPublicAccessBlock"] = None
    assert [a.resource for a in _paths(data)["public-bucket-without-backstop"].affected] == ["open"]


def test_attack_paths_only_build_on_real_checks():
    for _, _, _, _, _, builds_on, _, _ in sc.ATTACK_PATHS:
        assert set(builds_on) <= set(sc.CHECKS_BY_ID)


# ----------------------------------------------------------------- threats
def test_threats_group_guardduty_types_and_bundle_security_hub():
    data = clean_bundle(
        GuardDutyFindings=[
            {"Type": "Trojan:EC2/X", "Severity": 8.0, "Resource": {"ResourceType": "Instance"}, "Title": "t1"},
            {"Type": "Trojan:EC2/X", "Severity": 9.2},
            {"Type": "Recon:EC2/Probe", "Severity": 3.0},
        ],
        SecurityHubFindings=[
            {"Severity": {"Label": "HIGH"}, "Title": "h", "Resources": [{"Id": "arn:1"}]},
            {"Severity": {"Label": "CRITICAL"}, "Title": "c"},
            {"Severity": {"Label": "MEDIUM"}, "Title": "m"},
        ],
    )
    found = sc.threats(data, guardduty_severity_label)
    gd, sh = found
    assert gd.title == "GuardDuty: Trojan:EC2/X" and gd.severity == "CRITICAL" and len(gd.affected) == 2
    assert gd.affected[1].resource == "resource"
    assert sh.severity == "CRITICAL" and len(sh.affected) == 2 and sh.affected[1].resource == "?"


def test_security_hub_threat_is_high_without_critical_findings():
    data = clean_bundle(SecurityHubFindings=[{"Severity": {"Label": "HIGH"}, "Title": "h", "Resources": [{"Id": "x"}]}])
    (sh,) = sc.threats(data, guardduty_severity_label)
    assert sh.severity == "HIGH"


def test_detection_coverage_counts_service_region_pairs():
    data = clean_bundle(Macie={"Enabled": False}, ConfigRecorder={"Recording": False})
    assert sc.detection_coverage(data) == (3, 5)
    del data["Regions"]["us-east-1"]["Security"]["Inspector2"]
    assert sc.detection_coverage(data) == (2, 4)


def test_analyze_bundles_everything_the_report_needs():
    out = sc.analyze(clean_bundle(), guardduty_severity_label)
    assert set(out) == {"results", "paths", "threats", "actions", "score"}
    assert out["score"].score == 100 and out["actions"] == [] and out["paths"] == []


def test_region_with_missing_or_null_evidence_is_no_data():
    """A region whose bundle lacks a key (the WA evidence pack has no
    public-snapshot or default-SG data) or holds None must not pass."""
    data = clean_bundle(PublicRdsSnapshots=None)
    del data["Regions"]["us-east-1"]["WideOpenSecurityGroups"]
    del data["Regions"]["us-east-1"]["Security"]["AccessAnalyzerFindings"]
    statuses = _status(data)
    for check_id in ("rds-snapshot-public", "sg-high-risk-ports", "sg-unauthorized-ports", "access-analyzer-findings"):
        assert statuses[check_id] == engine.NO_DATA
