import boto3
from moto import mock_aws

from shared.awslib.collectors import cloudtrail
import pytest
from botocore.exceptions import ClientError
from tests.stub_helpers import install_stub


@mock_aws
def test_cloudtrail_posture_detects_multi_region_logging_trail(ctx):
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-bucket")
    s3.put_bucket_policy(
        Bucket="trail-bucket",
        Policy='{"Version": "2012-10-17", "Statement": []}',
    )
    ct.create_trail(Name="org-trail", S3BucketName="trail-bucket", IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="org-trail")

    posture = cloudtrail.cloudtrail_posture(ctx, "us-east-1")

    assert posture["HasMultiRegionTrail"] is True
    assert posture["HasLogFileValidation"] is True
    assert len(posture["Trails"]) == 1


@mock_aws
def test_cloudtrail_posture_empty_when_no_trail(ctx):
    posture = cloudtrail.cloudtrail_posture(ctx, "us-east-1")
    assert posture["HasMultiRegionTrail"] is False
    assert posture["HasLoggingTrail"] is False
    assert posture["Trails"] == []


def test_shadow_trail_status_is_read_by_arn(ctx):
    """A multi-region trail seen from a region other than its home region
    is a shadow trail. GetTrailStatus by *name* raises TrailNotFoundException
    for it, which aborted any security scan whose first region wasn't the
    trail's home. The Stubber pins that both calls pass the ARN."""
    arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"
    ct, stub = install_stub(ctx, "cloudtrail", region="eu-west-1")
    stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "main", "TrailARN": arn, "HomeRegion": "us-east-1", "IsMultiRegionTrail": True}]},
        {"includeShadowTrails": True},
    )
    stub.add_response("get_trail_status", {"IsLogging": True}, {"Name": arn})
    stub.add_response("get_event_selectors", {"TrailARN": arn, "EventSelectors": []}, {"TrailName": arn})

    posture = cloudtrail.cloudtrail_posture(ctx, "eu-west-1")
    assert posture["HasLoggingMultiRegionTrail"] is True
    stub.assert_no_pending_responses()


def test_unresolvable_trail_is_recorded_without_status(ctx):
    """An organization trail a member account can list but not resolve must
    not abort the scan; it is kept with unknown status."""
    arn = "arn:aws:cloudtrail:us-east-1:999999999999:trail/org"
    ct, stub = install_stub(ctx, "cloudtrail", region="us-east-1")
    stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "org", "TrailARN": arn, "IsMultiRegionTrail": True}]},
        {"includeShadowTrails": True},
    )
    stub.add_client_error("get_trail_status", service_error_code="TrailNotFoundException")
    stub.add_client_error("get_event_selectors", service_error_code="TrailNotFoundException")

    posture = cloudtrail.cloudtrail_posture(ctx, "us-east-1")
    assert posture["Trails"][0]["_Status"] is None
    assert posture["Trails"][0]["_EventSelectors"] == []
    assert posture["HasLoggingMultiRegionTrail"] is False


def test_unexpected_trail_status_errors_still_propagate(ctx):
    ct, stub = install_stub(ctx, "cloudtrail", region="us-east-1")
    stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t"}]},
        {"includeShadowTrails": True},
    )
    stub.add_client_error("get_trail_status", service_error_code="ThrottlingException")
    with pytest.raises(ClientError):
        cloudtrail.cloudtrail_posture(ctx, "us-east-1")


def test_logging_multi_region_trail_needs_one_trail_with_both_properties(ctx):
    """A stopped multi-region trail plus a logging single-region trail made
    both summary flags true although no trail meets CloudTrail.1."""
    ct, stub = install_stub(ctx, "cloudtrail", region="us-east-1")
    multi = "arn:aws:cloudtrail:us-east-1:123456789012:trail/multi-stopped"
    single = "arn:aws:cloudtrail:us-east-1:123456789012:trail/single-logging"
    stub.add_response(
        "describe_trails",
        {
            "trailList": [
                {"Name": "multi-stopped", "TrailARN": multi, "IsMultiRegionTrail": True},
                {"Name": "single-logging", "TrailARN": single, "IsMultiRegionTrail": False},
            ]
        },
        {"includeShadowTrails": True},
    )
    stub.add_response("get_trail_status", {"IsLogging": False}, {"Name": multi})
    stub.add_response("get_event_selectors", {"EventSelectors": []}, {"TrailName": multi})
    stub.add_response("get_trail_status", {"IsLogging": True}, {"Name": single})
    stub.add_response("get_event_selectors", {"EventSelectors": []}, {"TrailName": single})

    posture = cloudtrail.cloudtrail_posture(ctx, "us-east-1")
    assert posture["HasMultiRegionTrail"] is True
    assert posture["HasLoggingTrail"] is True
    assert posture["HasLoggingMultiRegionTrail"] is False


def test_unexpected_event_selector_errors_still_propagate(ctx):
    ct, stub = install_stub(ctx, "cloudtrail", region="us-east-1")
    arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/t"
    stub.add_response("describe_trails", {"trailList": [{"Name": "t", "TrailARN": arn}]}, {"includeShadowTrails": True})
    stub.add_response("get_trail_status", {"IsLogging": True}, {"Name": arn})
    stub.add_client_error("get_event_selectors", service_error_code="ThrottlingException")
    with pytest.raises(ClientError):
        cloudtrail.cloudtrail_posture(ctx, "us-east-1")

