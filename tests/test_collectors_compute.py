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


@mock_aws
def test_describe_load_balancers_v2_enriches_target_groups_and_listeners(ctx):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    subnet2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]

    elbv2 = boto3.client("elbv2", region_name="us-east-1")
    lb_arn = elbv2.create_load_balancer(Name="web", Subnets=[subnet1, subnet2])["LoadBalancers"][0]["LoadBalancerArn"]
    tg_arn = elbv2.create_target_group(Name="tg", Protocol="HTTP", Port=80, VpcId=vpc_id)["TargetGroups"][0]["TargetGroupArn"]
    elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    lbs = compute.describe_load_balancers_v2(ctx, "us-east-1")

    assert len(lbs) == 1
    assert [tg["TargetGroupArn"] for tg in lbs[0]["_TargetGroups"]] == [tg_arn]
    assert [ls["Port"] for ls in lbs[0]["_Listeners"]] == [80]


@mock_aws
def test_describe_acm_certificates_returns_full_detail(ctx):
    acm = boto3.client("acm", region_name="us-east-1")
    acm.request_certificate(DomainName="example.com", ValidationMethod="DNS")

    certs = compute.describe_acm_certificates(ctx, "us-east-1")

    assert len(certs) == 1
    # The list call returns summaries; the collector must follow up with
    # describe_certificate so expiry fields are available to the report.
    assert certs[0]["DomainName"] == "example.com"
    assert "Status" in certs[0]
