import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from shared.awslib.session import ignore_access_denied, manual_paginate
from tests.stub_helpers import install_stub


@mock_aws
def test_account_id_returns_caller_identity_account(ctx):
    assert ctx.account_id() == "123456789012"


@mock_aws
def test_enabled_regions_returns_sorted_region_names(ctx):
    regions = ctx.enabled_regions()
    assert isinstance(regions, list)
    assert regions == sorted(regions)
    assert "us-east-1" in regions


def test_client_is_cached_per_service_and_region(ctx):
    c1 = ctx.client("ec2", region="us-east-1")
    c2 = ctx.client("ec2", region="us-east-1")
    c3 = ctx.client("ec2", region="eu-west-1")
    assert c1 is c2
    assert c1 is not c3


@pytest.mark.parametrize(
    "error_code",
    [
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "OptInRequired",
        "SubscriptionRequiredException",
        "InvalidAction",
        "InvalidAccessException",
        "AWSOrganizationsNotInUseException",
        "DataUnavailableException",
    ],
)
def test_ignore_access_denied_swallows_every_documented_error_code(ctx, error_code):
    """Regression test: every error code ignore_access_denied claims to
    swallow must actually be swallowed -- a code silently missing from this
    parametrized list would mean a future collector using an untested code
    could crash instead of degrading gracefully (this is exactly the class
    of bug found earlier this session with SecurityHub's InvalidAccessException)."""

    @ignore_access_denied(default=list)
    def flaky():
        client = boto3.client("sts", region_name="us-east-1")
        error_response = {"Error": {"Code": error_code, "Message": "boom"}}
        raise client.exceptions.ClientError(error_response, "GetCallerIdentity")

    assert flaky() == []


def test_ignore_access_denied_reraises_unrelated_error_codes(ctx):
    """A throttling/transient error must propagate -- swallowing it would
    silently produce an empty, wrong-looking report instead of failing.
    Asserts the specific exception and code, not a bare Exception: a blind
    assertion would also pass on an unrelated AttributeError from a typo."""

    @ignore_access_denied(default=list)
    def flaky():
        client = boto3.client("sts", region_name="us-east-1")
        error_response = {"Error": {"Code": "ThrottlingException", "Message": "boom"}}
        raise client.exceptions.ClientError(error_response, "GetCallerIdentity")

    with pytest.raises(ClientError) as exc:
        flaky()
    assert exc.value.response["Error"]["Code"] == "ThrottlingException"


def test_ignore_access_denied_default_can_be_a_plain_value_not_just_callable():
    @ignore_access_denied(default=None)
    def flaky():
        client = boto3.client("sts", region_name="us-east-1")
        error_response = {"Error": {"Code": "AccessDenied", "Message": "boom"}}
        raise client.exceptions.ClientError(error_response, "GetCallerIdentity")

    assert flaky() is None


def test_manual_paginate_follows_next_token_across_multiple_pages(ctx):
    wa, stub = install_stub(ctx, "wellarchitected")
    stub.add_response(
        "list_workloads",
        {"WorkloadSummaries": [{"WorkloadId": "1" * 32, "WorkloadName": "alpha"}], "NextToken": "tok-1"},
    )
    stub.add_response(
        "list_workloads",
        {"WorkloadSummaries": [{"WorkloadId": "2" * 32, "WorkloadName": "bravo"}], "NextToken": "tok-2"},
    )
    stub.add_response(
        "list_workloads",
        {"WorkloadSummaries": [{"WorkloadId": "3" * 32, "WorkloadName": "charlie"}]},
    )

    results = list(manual_paginate(wa, "list_workloads", "WorkloadSummaries"))

    assert [w["WorkloadName"] for w in results] == ["alpha", "bravo", "charlie"]


def test_manual_paginate_single_page_stops_without_next_token(ctx):
    wa, stub = install_stub(ctx, "wellarchitected")
    stub.add_response("list_workloads", {"WorkloadSummaries": [{"WorkloadId": "1" * 32, "WorkloadName": "only"}]})

    results = list(manual_paginate(wa, "list_workloads", "WorkloadSummaries"))

    assert [w["WorkloadName"] for w in results] == ["only"]


def test_manual_paginate_empty_result_key_yields_nothing(ctx):
    wa, stub = install_stub(ctx, "wellarchitected")
    stub.add_response("list_workloads", {"WorkloadSummaries": []})

    assert list(manual_paginate(wa, "list_workloads", "WorkloadSummaries")) == []
