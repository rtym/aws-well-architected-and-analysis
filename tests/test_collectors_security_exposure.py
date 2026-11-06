"""Exposure/encryption checks added for FSBP-aligned coverage: EBS
encryption posture, public snapshots (EBS and RDS), RDS exposure, KMS
rotation, Lambda function URLs, account-level S3 Block Public Access,
Inspector/Macie enablement, and default-security-group hygiene."""
import io
import zipfile

import boto3
from moto import mock_aws

from shared.awslib.collectors import data_stores, security, vpc
from tests.stub_helpers import install_stub


# ----------------------------------------------------------- EBS encryption
@mock_aws
def test_ebs_encryption_by_default_reflects_the_regional_switch(ctx):
    assert security.ebs_encryption_by_default(ctx, "us-east-1") is False
    boto3.client("ec2", region_name="us-east-1").enable_ebs_encryption_by_default()
    assert security.ebs_encryption_by_default(ctx, "us-east-1") is True


@mock_aws
def test_unencrypted_ebs_volumes_lists_only_unencrypted(ctx):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    plain = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)["VolumeId"]
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)

    found = security.unencrypted_ebs_volumes(ctx, "us-east-1")
    assert [v["VolumeId"] for v in found] == [plain]
    assert found[0]["SizeGiB"] == 8


def test_public_ebs_snapshots_queries_the_restorable_by_all_filter(ctx):
    """moto's describe_snapshots ignores the OwnerIds/RestorableByUserIds
    request filters (it returned its ~1200 seeded AMI snapshots), so the
    server-side filter contract is pinned with a Stubber instead: "my
    snapshots, restorable by everyone" must be filtered by AWS, not here."""
    ec2, stub = install_stub(ctx, "ec2", region="us-east-1")
    stub.add_response(
        "describe_snapshots",
        {"Snapshots": [{"SnapshotId": "snap-public", "VolumeId": "vol-1"}]},
        {"OwnerIds": ["self"], "RestorableByUserIds": ["all"]},
    )
    found = security.public_ebs_snapshots(ctx, "us-east-1")
    assert found == [{"SnapshotId": "snap-public", "VolumeId": "vol-1"}]


# ----------------------------------------------------------------------- KMS
@mock_aws
def test_kms_keys_without_rotation_skips_rotated_and_asymmetric_keys(ctx):
    kms = boto3.client("kms", region_name="us-east-1")
    unrotated = kms.create_key(Description="app data key")["KeyMetadata"]["KeyId"]
    rotated = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=rotated)
    # Asymmetric keys can't auto-rotate -- they must not be flagged.
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")

    found = security.kms_keys_without_rotation(ctx, "us-east-1")
    assert [k["KeyId"] for k in found] == [unrotated]
    assert found[0]["Description"] == "app data key"


def test_kms_keys_without_rotation_skips_aws_managed_and_denied_keys(ctx):
    """A key policy can deny DescribeKey even when ListKeys succeeds; the
    scan must skip that key and keep going, and AWS-managed keys (which
    rotate automatically) must not be flagged."""
    kms, stub = install_stub(ctx, "kms", region="us-east-1")
    stub.add_response(
        "list_keys",
        {"Keys": [{"KeyId": "k-denied"}, {"KeyId": "k-aws"}, {"KeyId": "k-flag"}]},
        {},
    )
    stub.add_client_error("describe_key", service_error_code="AccessDeniedException")
    stub.add_response(
        "describe_key",
        {"KeyMetadata": {"KeyId": "k-aws", "KeyManager": "AWS", "KeyState": "Enabled"}},
        {"KeyId": "k-aws"},
    )
    stub.add_response(
        "describe_key",
        {
            "KeyMetadata": {
                "KeyId": "k-flag",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "Description": "db key",
            }
        },
        {"KeyId": "k-flag"},
    )
    stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": "k-flag"})

    found = security.kms_keys_without_rotation(ctx, "us-east-1")
    assert found == [{"KeyId": "k-flag", "Description": "db key"}]


def test_kms_keys_without_rotation_propagates_unexpected_errors(ctx):
    """Only AccessDenied/NotFound are per-key noise; anything else (e.g.
    throttling) must propagate rather than silently shrink the result."""
    import pytest
    from botocore.exceptions import ClientError

    kms, stub = install_stub(ctx, "kms", region="us-east-1")
    stub.add_response("list_keys", {"Keys": [{"KeyId": "k1"}]}, {})
    stub.add_client_error("describe_key", service_error_code="ThrottlingException")
    with pytest.raises(ClientError):
        security.kms_keys_without_rotation(ctx, "us-east-1")


# -------------------------------------------------------- Lambda function URLs
def _lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {}\n")
    return buf.getvalue()


@mock_aws
def test_lambda_urls_without_auth_flags_only_authtype_none(ctx):
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    for name in ("fn-open", "fn-iam", "fn-nourl"):
        lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role,
            Handler="index.handler",
            Code={"ZipFile": _lambda_zip()},
        )
    lam.create_function_url_config(FunctionName="fn-open", AuthType="NONE")
    lam.create_function_url_config(FunctionName="fn-iam", AuthType="AWS_IAM")

    found = security.lambda_urls_without_auth(ctx, "us-east-1")
    assert [f["FunctionName"] for f in found] == ["fn-open"]
    assert found[0]["FunctionUrl"]


# ----------------------------------------------------------------- RDS exposure
def test_rds_exposure_separates_public_and_unencrypted():
    instances = [
        {"DBInstanceIdentifier": "pub", "Engine": "postgres", "PubliclyAccessible": True, "StorageEncrypted": True},
        {"DBInstanceIdentifier": "plain", "Engine": "mysql", "PubliclyAccessible": False, "StorageEncrypted": False},
        {"DBInstanceIdentifier": "clean", "Engine": "postgres", "PubliclyAccessible": False, "StorageEncrypted": True},
    ]
    exposure = data_stores.rds_exposure(instances)
    assert [i["DBInstanceIdentifier"] for i in exposure["PubliclyAccessible"]] == ["pub"]
    assert [i["DBInstanceIdentifier"] for i in exposure["Unencrypted"]] == ["plain"]


@mock_aws
def test_public_rds_snapshots_flags_only_snapshots_shared_with_all(ctx):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="db1",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="secret123",
        AllocatedStorage=20,
    )
    rds.create_db_snapshot(DBInstanceIdentifier="db1", DBSnapshotIdentifier="snap-public")
    rds.create_db_snapshot(DBInstanceIdentifier="db1", DBSnapshotIdentifier="snap-private")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier="snap-public", AttributeName="restore", ValuesToAdd=["all"]
    )

    snapshots = data_stores.describe_rds_snapshots(ctx, "us-east-1")
    found = data_stores.public_rds_snapshots(ctx, "us-east-1", snapshots)
    assert [s["DBSnapshotIdentifier"] for s in found] == ["snap-public"]


def test_public_rds_snapshots_skips_entries_without_identifier(ctx):
    """A malformed snapshot record without DBSnapshotIdentifier must not
    produce a describe_db_snapshot_attributes call with a None argument."""
    rds, stub = install_stub(ctx, "rds", region="us-east-1")  # no expected calls
    assert data_stores.public_rds_snapshots(ctx, "us-east-1", [{}]) == []


# ------------------------------------------- Account-level S3 public access
@mock_aws
def test_account_public_access_block_none_when_never_configured(ctx):
    assert security.account_public_access_block(ctx) is None


@mock_aws
def test_account_public_access_block_returns_configuration(ctx):
    s3control = boto3.client("s3control", region_name="us-east-1")
    account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    s3control.put_public_access_block(
        AccountId=account,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )
    cfg = security.account_public_access_block(ctx)
    assert cfg["BlockPublicPolicy"] is False
    assert cfg["BlockPublicAcls"] is True


# -------------------------------------------------------- Inspector and Macie
def test_inspector2_status_enabled(ctx):
    sts, sts_stub = install_stub(ctx, "sts")
    sts_stub.add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/t", "UserId": "AIDA1"},
    )
    insp, stub = install_stub(ctx, "inspector2", region="us-east-1")
    # errorCode/errorMessage are schema-required in every State object even
    # for a healthy account (botocore validates stubs against the real shape).
    state = {"status": "ENABLED", "errorCode": "INTERNAL_ERROR", "errorMessage": "none"}
    stub.add_response(
        "batch_get_account_status",
        {
            "accounts": [
                {
                    "accountId": "123456789012",
                    "resourceState": {"ec2": state, "ecr": state},
                    "state": state,
                }
            ],
            "failedAccounts": [],
        },
        {"accountIds": ["123456789012"]},
    )
    assert security.inspector2_status(ctx, "us-east-1") == {"Enabled": True, "Status": "ENABLED"}


def test_inspector2_status_access_denied_means_not_enabled(ctx):
    sts, sts_stub = install_stub(ctx, "sts")
    sts_stub.add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/t", "UserId": "AIDA1"},
    )
    insp, stub = install_stub(ctx, "inspector2", region="us-east-1")
    stub.add_client_error("batch_get_account_status", service_error_code="AccessDeniedException")
    assert security.inspector2_status(ctx, "us-east-1") == {"Enabled": False, "Status": None}


def test_macie_status_enabled(ctx):
    macie, stub = install_stub(ctx, "macie2", region="us-east-1")
    stub.add_response("get_macie_session", {"status": "ENABLED"})
    assert security.macie_status(ctx, "us-east-1") == {"Enabled": True, "Status": "ENABLED"}


def test_macie_status_never_enabled_maps_access_denied_to_disabled(ctx):
    """Macie raises AccessDeniedException when it has never been enabled in
    a region -- the collector must report that as Enabled: False, not crash."""
    macie, stub = install_stub(ctx, "macie2", region="us-east-1")
    stub.add_client_error(
        "get_macie_session",
        service_error_code="AccessDeniedException",
        service_message="Macie is not enabled.",
    )
    assert security.macie_status(ctx, "us-east-1") == {"Enabled": False, "Status": None}


def test_macie_status_paused_is_not_enabled(ctx):
    macie, stub = install_stub(ctx, "macie2", region="us-east-1")
    stub.add_response("get_macie_session", {"status": "PAUSED"})
    assert security.macie_status(ctx, "us-east-1") == {"Enabled": False, "Status": "PAUSED"}


# ---------------------------------------------------- Default security groups
def test_default_security_groups_with_rules_flags_only_defaults_with_rules():
    groups = [
        {"GroupId": "sg-app", "GroupName": "app", "IpPermissions": [{"FromPort": 443}], "IpPermissionsEgress": []},
        {
            "GroupId": "sg-def-dirty",
            "GroupName": "default",
            "VpcId": "vpc-1",
            "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-def-dirty"}]}],
            "IpPermissionsEgress": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        },
        {"GroupId": "sg-def-clean", "GroupName": "default", "VpcId": "vpc-2", "IpPermissions": [], "IpPermissionsEgress": []},
    ]
    found = vpc.default_security_groups_with_rules(groups)
    assert [f["GroupId"] for f in found] == ["sg-def-dirty"]
    assert found[0]["IngressRules"] == 1
    assert found[0]["EgressRules"] == 1


def test_collect_region_security_includes_the_new_exposure_keys(monkeypatch, ctx):
    """collect_region_security is the bundle both the security scan and the
    WA review consume -- the new checks must ship in it."""
    for fn in (
        "guardduty_status",
        "guardduty_findings",
        "securityhub_status",
        "securityhub_findings",
        "securityhub_standards_summary",
        "inspector2_status",
        "macie_status",
        "access_analyzer_findings",
        "config_rule_compliance",
        "config_recorder_status",
        "ebs_encryption_by_default",
        "unencrypted_ebs_volumes",
        "public_ebs_snapshots",
        "kms_keys_without_rotation",
        "lambda_urls_without_auth",
    ):
        monkeypatch.setattr(security, fn, lambda ctx, region, _fn=fn: _fn)

    out = security.collect_region_security(ctx, "us-east-1")
    assert set(out) == {
        "Region",
        "GuardDuty",
        "GuardDutyFindings",
        "SecurityHub",
        "SecurityHubFindings",
        "SecurityHubStandardsSummary",
        "Inspector2",
        "Macie",
        "AccessAnalyzerFindings",
        "ConfigRuleCompliance",
        "ConfigRecorder",
        "EbsEncryptionByDefault",
        "UnencryptedEbsVolumes",
        "PublicEbsSnapshots",
        "KmsKeysWithoutRotation",
        "LambdaUrlsWithoutAuth",
    }
    assert out["Inspector2"] == "inspector2_status"
    assert out["EbsEncryptionByDefault"] == "ebs_encryption_by_default"
