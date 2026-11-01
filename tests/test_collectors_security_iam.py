
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

def test_iam_findings_flags_root_mfa_and_root_access_key():
    """Root-account risks are the highest-priority IAM signal the security
    report surfaces -- the detection itself was previously untested."""
    report = [
        {
            "user": "<root_account>",
            "password_enabled": "not_supported",
            "mfa_active": "false",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2020-01-01T00:00:00+00:00",
            "access_key_2_active": "false",
        }
    ]
    findings = security.iam_findings(report, password_policy={"MinimumPasswordLength": 12})
    assert "root account has no MFA" in findings["RootAccountRisks"]
    assert "root account has an active access key" in findings["RootAccountRisks"]
    assert findings["PasswordPolicySet"] is True
    # The root user's active key is also tracked for rotation review.
    assert findings["AccessKeysToReview"] == [
        {"user": "<root_account>", "key": "1", "last_rotated": "2020-01-01T00:00:00+00:00"}
    ]


def test_iam_findings_clean_root_reports_no_risks():
    report = [
        {
            "user": "<root_account>",
            "mfa_active": "true",
            "access_key_1_active": "false",
            "access_key_2_active": "false",
        }
    ]
    findings = security.iam_findings(report, password_policy=None)
    assert findings["RootAccountRisks"] == []
    assert findings["ConsoleUsersWithoutMfa"] == []
    assert findings["AccessKeysToReview"] == []


def test_iam_findings_never_rotated_key_is_not_listed_for_review():
    """A key whose last_rotated is N/A (never used/rotated tracking absent)
    must not produce a bogus review row."""
    report = [
        {"user": "ci", "access_key_1_active": "true", "access_key_1_last_rotated": "N/A"}
    ]
    assert security.iam_findings(report, None)["AccessKeysToReview"] == []


@mock_aws
def test_iam_roles_listed(ctx):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument="{}")

    roles = security.iam_roles(ctx)
    assert any(r["RoleName"] == "app-role" for r in roles)


@mock_aws
def test_collect_global_security_assembles_iam_evidence(ctx):
    """The one-call entry point the security and WA scripts use: every key
    the reports read must be present and derived from the same credential
    report."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="carol")
    iam.create_login_profile(UserName="carol", Password="x", PasswordResetRequired=False)

    out = security.collect_global_security(ctx)
    assert set(out) == {"IamUsers", "IamRoles", "IamCredentialReport", "IamPasswordPolicy", "IamFindings"}
    assert any(u["UserName"] == "carol" for u in out["IamUsers"])
    assert "carol" in out["IamFindings"]["ConsoleUsersWithoutMfa"]
    assert out["IamFindings"]["PasswordPolicySet"] is (out["IamPasswordPolicy"] is not None)
