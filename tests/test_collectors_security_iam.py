
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
    # The root user's years-old active key is also tracked for rotation review.
    (key_row,) = findings["AccessKeysToReview"]
    assert key_row["user"] == "<root_account>"
    assert key_row["key"] == "1"
    assert key_row["age_days"] > 90


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


def test_iam_findings_fresh_key_is_not_listed_for_review():
    """FSBP IAM.3 sets the threshold at 90 days. Pre-threshold, the report
    listed every active key, which buried genuinely stale ones."""
    from datetime import datetime, timedelta, timezone

    fresh = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    report = [
        {"user": "fresh", "access_key_1_active": "true", "access_key_1_last_rotated": fresh},
        {"user": "stale", "access_key_1_active": "true", "access_key_1_last_rotated": old},
    ]
    findings = security.iam_findings(report, None)
    assert [k["user"] for k in findings["AccessKeysToReview"]] == ["stale"]
    assert 119 <= findings["AccessKeysToReview"][0]["age_days"] <= 121


def test_iam_findings_unparseable_rotation_date_is_listed():
    """"no_information" is not proof of freshness -- surface the key with an
    unknown age rather than silently dropping it."""
    report = [
        {"user": "mystery", "access_key_2_active": "true", "access_key_2_last_rotated": "no_information"}
    ]
    findings = security.iam_findings(report, None)
    assert findings["AccessKeysToReview"] == [
        {"user": "mystery", "key": "2", "last_rotated": "no_information", "age_days": None}
    ]


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


def test_key_age_treats_a_timestamp_without_offset_as_utc():
    """Subtracting a naive timestamp from an aware "now" raises TypeError;
    a credential report row without an offset must still be aged."""
    from datetime import datetime, timedelta, timezone

    naive = (datetime.now(timezone.utc) - timedelta(days=200)).replace(tzinfo=None).isoformat()
    report = [{"user": "legacy", "access_key_1_active": "true", "access_key_1_last_rotated": naive}]
    (row,) = security.iam_findings(report, None)["AccessKeysToReview"]
    assert 199 <= row["age_days"] <= 201

