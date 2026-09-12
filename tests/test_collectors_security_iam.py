
import boto3
from moto import mock_aws

from shared.awslib.collectors import security


@mock_aws
def test_iam_credential_report_and_findings_flag_missing_mfa(ctx):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="x", PasswordResetRequired=False)
    iam.create_access_key(UserName="alice")

    report = security.iam_credential_report(ctx)
    row = next(r for r in report if r["user"] == "alice")
    assert row["password_enabled"] == "true"
    assert row["mfa_active"] == "false"

    findings = security.iam_findings(report, password_policy=None)
    assert "alice" in findings["ConsoleUsersWithoutMfa"]
    assert findings["PasswordPolicySet"] is False


@mock_aws
def test_iam_users_include_mfa_and_access_key_metadata(ctx):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bob")
    iam.create_access_key(UserName="bob")

    users = security.iam_users(ctx)
    bob = next(u for u in users if u["UserName"] == "bob")
    assert len(bob["_AccessKeys"]) == 1
    assert bob["_MfaDevices"] == []


@mock_aws
def test_guardduty_status_reports_enabled_when_detector_exists(ctx):
    gd = boto3.client("guardduty", region_name="us-east-1")
    gd.create_detector(Enable=True)

    status = security.guardduty_status(ctx, "us-east-1")
    assert status["Enabled"] is True
    assert len(status["DetectorIds"]) == 1


@mock_aws
def test_guardduty_status_disabled_when_no_detector(ctx):
    status = security.guardduty_status(ctx, "us-east-1")
    assert status["Enabled"] is False
    assert status["DetectorIds"] == []
