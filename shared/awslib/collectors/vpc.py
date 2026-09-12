"""Network inventory: VPCs, subnets, route tables, gateways, endpoints, peering,
Transit Gateway attachments, security groups, NACLs, and flow-log configuration.

Every function returns plain JSON-serializable dict/list data (boto3 already
returns datetimes for some fields -- callers should pass results through
`shared.reporting.jsonutil.default` when serializing, see reporting/report.py).
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


def describe_vpcs(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    vpcs = list(paginate(ec2, "describe_vpcs", "Vpcs"))
    for vpc in vpcs:
        vpc["_FlowLogs"] = describe_flow_logs(ctx, region, resource_id=vpc["VpcId"])
    return vpcs


def describe_subnets(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_subnets", "Subnets"))


def describe_route_tables(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_route_tables", "RouteTables"))


def describe_internet_gateways(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_internet_gateways", "InternetGateways"))


def describe_nat_gateways(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_nat_gateways", "NatGateways"))


def describe_vpc_endpoints(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"))


def describe_vpc_peering_connections(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"))


@ignore_access_denied(default=list)
def describe_transit_gateway_attachments(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(
        paginate(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
    )


def describe_security_groups(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_security_groups", "SecurityGroups"))


def describe_network_acls(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_network_acls", "NetworkAcls"))


def describe_flow_logs(ctx: AwsContext, region: str, resource_id: str | None = None) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    kwargs = {}
    if resource_id:
        kwargs["Filter"] = [{"Name": "resource-id", "Values": [resource_id]}]
    return list(paginate(ec2, "describe_flow_logs", "FlowLogs", **kwargs))


def wide_open_security_groups(security_groups: list[dict]) -> list[dict]:
    """Security groups with an inbound rule open to 0.0.0.0/0 or ::/0."""
    findings = []
    for sg in security_groups:
        for perm in sg.get("IpPermissions", []):
            open_v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            open_v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
            if open_v4 or open_v6:
                findings.append(
                    {
                        "GroupId": sg["GroupId"],
                        "GroupName": sg.get("GroupName"),
                        "VpcId": sg.get("VpcId"),
                        "FromPort": perm.get("FromPort"),
                        "ToPort": perm.get("ToPort"),
                        "IpProtocol": perm.get("IpProtocol"),
                        "OpenRanges": [r.get("CidrIp") for r in open_v4]
                        + [r.get("CidrIpv6") for r in open_v6],
                    }
                )
    return findings


def collect_region_network(ctx: AwsContext, region: str) -> dict:
    """Full network inventory for one region."""
    security_groups = describe_security_groups(ctx, region)
    return {
        "Region": region,
        "Vpcs": describe_vpcs(ctx, region),
        "Subnets": describe_subnets(ctx, region),
        "RouteTables": describe_route_tables(ctx, region),
        "InternetGateways": describe_internet_gateways(ctx, region),
        "NatGateways": describe_nat_gateways(ctx, region),
        "VpcEndpoints": describe_vpc_endpoints(ctx, region),
        "VpcPeeringConnections": describe_vpc_peering_connections(ctx, region),
        "TransitGatewayAttachments": describe_transit_gateway_attachments(ctx, region),
        "SecurityGroups": security_groups,
        "NetworkAcls": describe_network_acls(ctx, region),
        "WideOpenSecurityGroupRules": wide_open_security_groups(security_groups),
    }
