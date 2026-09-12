import boto3
from moto import mock_aws

from shared.awslib.collectors import vpc
from tests.stub_helpers import install_stub


def test_describe_transit_gateway_attachments_returns_empty_on_access_denied(ctx):
    """Regression test: this used to catch a bare ec2.exceptions.ClientError
    (any failure, not just AccessDenied) inconsistently with every sibling
    collector's ignore_access_denied pattern -- now it should behave the
    same as the rest: swallow AccessDenied specifically."""
    ec2, stub = install_stub(ctx, "ec2")
    stub.add_client_error(
        "describe_transit_gateway_attachments", service_error_code="UnauthorizedOperation"
    )

    assert vpc.describe_transit_gateway_attachments(ctx, "us-east-1") == []


@mock_aws
def test_describe_transit_gateway_attachments_returns_real_data(ctx):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    tgw_id = ec2.create_transit_gateway()["TransitGateway"]["TransitGatewayId"]
    ec2.create_transit_gateway_vpc_attachment(TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[])

    attachments = vpc.describe_transit_gateway_attachments(ctx, "us-east-1")

    assert any(a["TransitGatewayId"] == tgw_id for a in attachments)


@mock_aws
def test_collect_region_network_detects_wide_open_security_group(ctx):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    sg_id = ec2.create_security_group(GroupName="open-ssh", Description="test", VpcId=vpc_id)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = vpc.collect_region_network(ctx, "us-east-1")

    assert any(v["VpcId"] == vpc_id for v in result["Vpcs"])
    assert any(s["VpcId"] == vpc_id for s in result["Subnets"])
    assert any(igw["InternetGatewayId"] == igw_id for igw in result["InternetGateways"])
    assert len(result["WideOpenSecurityGroupRules"]) == 1
    finding = result["WideOpenSecurityGroupRules"][0]
    assert finding["GroupId"] == sg_id
    assert finding["FromPort"] == 22
    assert "0.0.0.0/0" in finding["OpenRanges"]


@mock_aws
def test_wide_open_security_groups_ignores_restricted_rules():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg_id = ec2.create_security_group(GroupName="internal", Description="test", VpcId=vpc_id)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            }
        ],
    )
    sgs = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]

    assert vpc.wide_open_security_groups(sgs) == []
