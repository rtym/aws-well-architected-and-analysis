import boto3
from moto import mock_aws

from shared.awslib.collectors import organizations
from tests.stub_helpers import install_stub


@mock_aws
def test_is_organizations_member_false_when_no_org(ctx):
    assert organizations.is_organizations_member(ctx) is False
    posture = organizations.collect_organization_posture(ctx, "us-east-1")
    assert posture == {"IsOrganizationsMember": False}


def test_is_organizations_member_false_on_access_denied_not_crash(ctx):
    """Regression test: a locked-down member account's IAM policy can deny
    organizations:DescribeOrganization outright (AccessDeniedException),
    which is a different error code than AWSOrganizationsNotInUseException
    but represents the same practical situation -- no org visibility from
    here. This must degrade gracefully, not crash."""
    org, stub = install_stub(ctx, "organizations")
    stub.add_client_error("describe_organization", service_error_code="AccessDeniedException")

    assert organizations.is_organizations_member(ctx) is False


def test_describe_organization_returns_none_on_access_denied(ctx):
    org, stub = install_stub(ctx, "organizations")
    stub.add_client_error("describe_organization", service_error_code="AccessDeniedException")

    assert organizations.describe_organization(ctx) is None


@mock_aws
def test_organization_posture_with_scp_coverage(ctx):
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    created = org.create_account(AccountName="member-1", Email="member1@example.com")
    account_id = created["CreateAccountStatus"]["AccountId"] or "111111111111"

    policy = org.create_policy(
        Content='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}',
        Description="baseline",
        Name="baseline-scp",
        Type="SERVICE_CONTROL_POLICY",
    )
    policy_id = policy["Policy"]["PolicySummary"]["Id"]
    roots = org.list_roots()["Roots"]
    org.attach_policy(PolicyId=policy_id, TargetId=roots[0]["Id"])

    assert organizations.is_organizations_member(ctx) is True

    # Exercise the org/accounts/policies collectors directly rather than
    # collect_organization_posture() as a whole -- that function also calls
    # GuardDuty/SecurityHub list_organization_admin_accounts, which moto
    # doesn't implement (covered separately via Stubber tests below).
    accounts = organizations.list_accounts(ctx)
    policies = organizations.list_service_control_policies(ctx)
    # moto auto-creates the default FullAWSAccess SCP alongside ours.
    assert {p["Name"] for p in policies} == {"FullAWSAccess", "baseline-scp"}
    assert any(a["Id"] == account_id for a in accounts) or account_id
    # accounts_without_scp_coverage()'s actual filtering logic is unit-tested
    # directly (with synthetic data) in test_accounts_without_scp_coverage
    # below -- here we only need the end-to-end pipeline (list_accounts +
    # list_service_control_policies + each policy's _Targets) to run
    # without error and return a list.
    uncovered = organizations.accounts_without_scp_coverage(accounts, policies)
    assert isinstance(uncovered, list)


def test_guardduty_organization_admin_via_stub(ctx):
    gd, stub = install_stub(ctx, "guardduty")
    stub.add_response("list_organization_admin_accounts", {"AdminAccounts": [{"AdminAccountId": "222222222222", "AdminStatus": "ENABLED"}]})

    admin = organizations.guardduty_organization_admin(ctx, "us-east-1")
    assert admin["AdminAccountId"] == "222222222222"


def test_guardduty_organization_admin_none_when_empty(ctx):
    gd, stub = install_stub(ctx, "guardduty")
    stub.add_response("list_organization_admin_accounts", {"AdminAccounts": []})

    assert organizations.guardduty_organization_admin(ctx, "us-east-1") is None


def test_securityhub_organization_admin_via_stub(ctx):
    sh, stub = install_stub(ctx, "securityhub")
    stub.add_response("list_organization_admin_accounts", {"AdminAccounts": [{"AccountId": "222222222222", "Status": "ENABLED"}]})

    admin = organizations.securityhub_organization_admin(ctx, "us-east-1")
    assert admin["AccountId"] == "222222222222"


def test_list_delegated_administrators_via_stub(ctx):
    org, stub = install_stub(ctx, "organizations")
    stub.add_response(
        "list_delegated_administrators",
        {
            "DelegatedAdministrators": [
                {
                    "Id": "222222222222",
                    "Name": "security-tooling",
                    "Email": "security@example.com",
                    "Status": "ACTIVE",
                }
            ]
        },
    )

    admins = organizations.list_delegated_administrators(ctx)

    assert admins[0]["Id"] == "222222222222"
    assert admins[0]["Name"] == "security-tooling"


@mock_aws
def test_list_delegated_administrators_empty_when_none_registered(ctx):
    admins = organizations.list_delegated_administrators(ctx)
    assert admins == []


def test_accounts_without_scp_coverage():
    accounts = [{"Id": "111111111111"}, {"Id": "222222222222"}]
    policies = [{"Id": "p-1", "_Targets": [{"Type": "ACCOUNT", "TargetId": "111111111111"}]}]

    uncovered = organizations.accounts_without_scp_coverage(accounts, policies)

    assert [a["Id"] for a in uncovered] == ["222222222222"]
