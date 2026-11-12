import boto3
from moto import mock_aws

from shared.awslib.collectors import compute
from tests.stub_helpers import install_stub


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


def test_imdsv1_check_skips_disabled_endpoint_and_terminated_instances():
    """With the metadata endpoint switched off there is no IMDSv1 to abuse,
    and a terminated instance (listed for about an hour) no longer exists;
    both used to be flagged."""
    instances = [
        {"InstanceId": "i-open", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}},
        {"InstanceId": "i-off", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "disabled"}},
        {"InstanceId": "i-gone", "State": {"Name": "terminated"}, "MetadataOptions": {"HttpTokens": "optional"}},
        {"InstanceId": "i-v2", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "required"}},
        {"InstanceId": "i-stopped", "State": {"Name": "stopped"}, "MetadataOptions": {"HttpTokens": "optional"}},
    ]
    found = [i["InstanceId"] for i in compute.instances_allowing_imdsv1(instances)]
    assert found == ["i-open", "i-stopped"]


def test_http_listener_that_redirects_to_https_is_not_plaintext():
    """An HTTP:80 listener whose only action redirects to HTTPS is the
    recommended setup (FSBP ELB.1); flagging it put nearly every
    well-configured ALB in the "without TLS" table."""
    lbs = [
        {
            "LoadBalancerArn": "arn:lb",
            "LoadBalancerName": "web",
            "_Listeners": [
                {"Protocol": "HTTP", "Port": 80, "DefaultActions": [
                    {"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}
                ]},
                {"Protocol": "HTTP", "Port": 8080, "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg"}]},
                {"Protocol": "HTTP", "Port": 8081, "DefaultActions": [
                    {"Type": "redirect", "RedirectConfig": {"Protocol": "HTTP", "Port": "80", "StatusCode": "HTTP_302"}}
                ]},
                {"Protocol": "HTTP", "Port": 8082},
                {"Protocol": "HTTPS", "Port": 443, "DefaultActions": [{"Type": "forward"}]},
                {"Protocol": "TCP", "Port": 5432, "DefaultActions": [{"Type": "forward"}]},
                # TLS passthrough on a Network Load Balancer: the targets
                # terminate TLS, so this is not a plaintext listener.
                {"Protocol": "TCP", "Port": 443, "DefaultActions": [{"Type": "forward"}]},
            ],
        }
    ]
    found = [(f["Protocol"], f["Port"]) for f in compute.plaintext_load_balancer_listeners(lbs)]
    assert found == [("HTTP", 8080), ("HTTP", 8081), ("HTTP", 8082), ("TCP", 5432)]


def test_acm_listing_requests_every_key_type(ctx):
    """ListCertificates returns only RSA_1024/RSA_2048 certificates unless asked;
    ECDSA and larger RSA certificates never reached the expiry check. The
    list must track botocore's own enum, so a key type AWS adds later
    fails this test instead of being skipped silently."""
    import botocore.session

    acm, stub = install_stub(ctx, "acm", region="us-east-1")
    stub.add_response(
        "list_certificates",
        {"CertificateSummaryList": []},
        {"Includes": {"keyTypes": compute.ACM_ALL_KEY_TYPES}},
    )
    assert compute.describe_acm_certificates(ctx, "us-east-1") == []
    stub.assert_no_pending_responses()

    enum = botocore.session.get_session().get_service_model("acm").shape_for("KeyAlgorithm").enum
    assert sorted(compute.ACM_ALL_KEY_TYPES) == sorted(enum)
