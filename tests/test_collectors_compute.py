import boto3
from moto import mock_aws

from shared.awslib.collectors import compute


@mock_aws
def test_collect_region_compute_flags_unattached_volume_and_unassociated_eip(ctx):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ami_id = list(ec2.describe_images()["Images"])[0]["ImageId"] if ec2.describe_images()["Images"] else "ami-12345678"
    ec2.run_instances(ImageId=ami_id, MinCount=1, MaxCount=1, InstanceType="t3.micro")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)
    ec2.allocate_address(Domain="vpc")

    result = compute.collect_region_compute(ctx, "us-east-1")

    assert len(result["Instances"]) == 1
    assert len(result["UnattachedVolumes"]) == 1
    assert len(result["UnassociatedEips"]) == 1


@mock_aws
def test_idle_instance_candidates_only_returns_stopped():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    images = ec2.describe_images()["Images"]
    ami_id = images[0]["ImageId"] if images else "ami-12345678"
    instance_id = ec2.run_instances(ImageId=ami_id, MinCount=1, MaxCount=1, InstanceType="t3.micro")[
        "Instances"
    ][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[instance_id])

    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    instances = [i for r in reservations for i in r["Instances"]]

    stopped = compute.idle_instance_candidates(instances)
    assert len(stopped) == 1
    assert stopped[0]["InstanceId"] == instance_id
