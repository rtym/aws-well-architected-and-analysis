import boto3
from moto import mock_aws

from shared.awslib.collectors import cloudtrail


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
