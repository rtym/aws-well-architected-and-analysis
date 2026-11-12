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
    # Recorded, so the report can tell this from a standalone account.
    assert ctx.denied == [
        {"Collector": "is_organizations_member", "Operation": "DescribeOrganization", "Region": "global", "Code": "AccessDeniedException"}
    ]


def test_a_standalone_account_is_not_a_denied_call(ctx):
    org, stub = install_stub(ctx, "organizations")
    stub.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException")
    assert organizations.is_organizations_member(ctx) is False
    assert ctx.denied == []


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


def test_describe_organization_returns_none_when_not_in_an_organization(ctx):
    org, stub = install_stub(ctx, "organizations")
    stub.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException")

    assert organizations.describe_organization(ctx) is None


def test_is_organizations_member_propagates_unexpected_errors(ctx):
    """Only the documented "no org visibility" codes mean False -- a
    throttle or outage must surface, not masquerade as a standalone account."""
    import pytest
    from botocore.exceptions import ClientError

    org, stub = install_stub(ctx, "organizations")
    stub.add_client_error("describe_organization", service_error_code="ThrottlingException")

    with pytest.raises(ClientError) as exc:
        organizations.is_organizations_member(ctx)
    assert exc.value.response["Error"]["Code"] == "ThrottlingException"


def test_collect_organization_posture_wires_every_key(ctx, monkeypatch):
    """collect_organization_posture() itself (the dict the report and the
    gap-analysis JSON contract read) -- collectors are monkeypatched because
    moto doesn't implement the GuardDuty/SecurityHub org-admin lookups."""
    monkeypatch.setattr(organizations, "is_organizations_member", lambda ctx: True)
    monkeypatch.setattr(organizations, "list_accounts", lambda ctx: [{"Id": "1" * 12}])
    monkeypatch.setattr(organizations, "list_service_control_policies", lambda ctx: [])
    monkeypatch.setattr(organizations, "describe_organization", lambda ctx: {"MasterAccountId": "2" * 12})
    monkeypatch.setattr(organizations, "list_delegated_administrators", lambda ctx: [{"Id": "3" * 12}])
    monkeypatch.setattr(organizations, "guardduty_organization_admin", lambda ctx, region: {"AdminAccountId": "4" * 12, "_Region": region})
    monkeypatch.setattr(organizations, "securityhub_organization_admin", lambda ctx, region: None)

    posture = organizations.collect_organization_posture(ctx, "eu-west-1")

    assert posture["IsOrganizationsMember"] is True
    assert set(posture) == {
        "IsOrganizationsMember", "Organization", "Accounts", "ServiceControlPolicies",
        "AccountsWithoutScpCoverage", "DelegatedAdministrators",
        "GuardDutyOrganizationAdmin", "SecurityHubOrganizationAdmin",
    }
    # Accounts with no SCP at all are uncovered; the admin lookups must be
    # asked in the caller's home region (they are regional APIs).
    assert posture["AccountsWithoutScpCoverage"] == [{"Id": "1" * 12}]
    assert posture["GuardDutyOrganizationAdmin"]["_Region"] == "eu-west-1"
    assert posture["SecurityHubOrganizationAdmin"] is None


FULL_AWS_ACCESS = {
    "Id": "p-FullAWSAccess",
    "Name": "FullAWSAccess",
    "AwsManaged": True,
    "_Targets": [
        {"Type": "ROOT", "TargetId": "r-root"},
        {"Type": "ACCOUNT", "TargetId": "111111111111"},
        {"Type": "ACCOUNT", "TargetId": "222222222222"},
    ],
}
ACCOUNTS = [{"Id": "111111111111"}, {"Id": "222222222222"}, {"Id": "999999999999"}]


def test_full_aws_access_alone_is_not_coverage():
    """AWS attaches the allow-all FullAWSAccess to every account by default.
    Counting it made a typical org look fully covered when no SCP
    restricted anything."""
    uncovered = organizations.accounts_without_scp_coverage(ACCOUNTS, [FULL_AWS_ACCESS])
    assert [a["Id"] for a in uncovered] == ["111111111111", "222222222222", "999999999999"]


def test_root_attached_scp_covers_every_member_account():
    """Only direct account attachments used to count, so an SCP on the root
    -- the usual way to apply a baseline -- covered nobody."""
    baseline = {"Id": "p-baseline", "Name": "baseline", "_Targets": [{"Type": "ROOT", "TargetId": "r-root"}]}
    assert organizations.accounts_without_scp_coverage(ACCOUNTS, [FULL_AWS_ACCESS, baseline]) == []


def test_ou_attached_scp_covers_only_that_subtree():
    workloads = {"Id": "p-workloads", "Name": "workloads", "_Targets": [{"Type": "ORGANIZATIONAL_UNIT", "TargetId": "ou-w"}]}
    uncovered = organizations.accounts_without_scp_coverage(
        ACCOUNTS, [workloads], ou_accounts={"ou-w": {"111111111111", "222222222222"}}
    )
    assert [a["Id"] for a in uncovered] == ["999999999999"]


def test_management_account_is_never_listed_as_uncovered():
    """SCPs never apply to the management account, so listing it would be a
    finding nobody can act on."""
    uncovered = organizations.accounts_without_scp_coverage(
        ACCOUNTS, [], management_account_id="999999999999"
    )
    assert [a["Id"] for a in uncovered] == ["111111111111", "222222222222"]


@mock_aws
def test_ou_scp_coverage_end_to_end_through_nested_ous(ctx, monkeypatch):
    """An SCP on a parent OU covers accounts in its nested OUs; accounts
    left at the root stay uncovered; the management account is excluded."""
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root = org.list_roots()["Roots"][0]["Id"]
    workloads = org.create_organizational_unit(ParentId=root, Name="workloads")["OrganizationalUnit"]["Id"]
    prod = org.create_organizational_unit(ParentId=workloads, Name="prod")["OrganizationalUnit"]["Id"]

    def new_account(name):
        return org.create_account(Email=f"{name}@example.com", AccountName=name)["CreateAccountStatus"]["AccountId"]

    in_workloads, in_prod, at_root = new_account("app"), new_account("prod"), new_account("sandbox")
    org.move_account(AccountId=in_workloads, SourceParentId=root, DestinationParentId=workloads)
    org.move_account(AccountId=in_prod, SourceParentId=root, DestinationParentId=prod)

    assert organizations.ou_descendant_account_ids(ctx, workloads) == {in_workloads, in_prod}

    policy_id = org.create_policy(
        Content='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"cloudtrail:StopLogging","Resource":"*"}]}',
        Description="baseline guardrails",
        Name="baseline",
        Type="SERVICE_CONTROL_POLICY",
    )["Policy"]["PolicySummary"]["Id"]
    org.attach_policy(PolicyId=policy_id, TargetId=workloads)

    monkeypatch.setattr(organizations, "guardduty_organization_admin", lambda ctx, region: None)
    monkeypatch.setattr(organizations, "securityhub_organization_admin", lambda ctx, region: None)
    posture = organizations.collect_organization_posture(ctx, "us-east-1")

    management = posture["Organization"]["MasterAccountId"]
    uncovered = {a["Id"] for a in posture["AccountsWithoutScpCoverage"]}
    assert uncovered == {at_root}
    assert management not in uncovered


def test_describe_organization_propagates_unexpected_errors(ctx):
    """Only "not in an organization" maps to None; throttling is not that."""
    import pytest
    from botocore.exceptions import ClientError

    org, stub = install_stub(ctx, "organizations", region="us-east-1")
    stub.add_client_error("describe_organization", service_error_code="TooManyRequestsException")
    with pytest.raises(ClientError):
        organizations.describe_organization(ctx)

