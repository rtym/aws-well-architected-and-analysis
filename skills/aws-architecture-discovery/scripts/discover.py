#!/usr/bin/env python3
"""Extract a full infrastructure inventory from an AWS account/region set:
VPCs, subnets, route tables, gateways, endpoints, peering, Transit Gateway
attachments, security groups, NACLs, EC2, ASGs, EBS, ELB/ALB/NLB, ECS, EKS,
RDS, DynamoDB, ElastiCache, Lambda, and S3 -- plus a Markdown/HTML/PDF report
with per-region resource-count charts and Mermaid topology diagrams.

Read-only. Every AWS call here is a Describe/List/Get operation.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions  # noqa: E402
from shared.awslib.collectors import compute, containers, data_stores, vpc  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Discover AWS network, compute, container, and data-store inventory.")
    parser.add_argument("--regions", default=None, help="Comma-separated regions (default: --region only)")
    parser.add_argument("--all-regions", action="store_true", help="Scan every region enabled for this account")
    return parser.parse_args(argv)


def collect(ctx, regions: list[str]) -> dict:
    inventory = {"AccountId": None, "Regions": {}}
    try:
        inventory["AccountId"] = ctx.account_id()
    except (ClientError, BotoCoreError):
        # The account ID is a nice-to-have label on the report, not evidence.
        # Narrowly scoped to credential-resolution and API errors so a real
        # bug (an AttributeError, say) still surfaces instead of silently
        # producing a report labelled "unknown".
        inventory["AccountId"] = None
    for region in regions:
        inventory["Regions"][region] = {
            "Network": vpc.collect_region_network(ctx, region),
            "Compute": compute.collect_region_compute(ctx, region),
            "Containers": containers.collect_region_containers(ctx, region),
            "DataStores": data_stores.collect_region_data_stores(ctx, region),
        }
    inventory["Global"] = {"DataStores": data_stores.collect_global_data_stores(ctx)}
    return inventory


def resource_counts_by_region(inventory: dict) -> dict[str, dict[str, int]]:
    counts = {}
    for region, data in inventory["Regions"].items():
        counts[region] = {
            "VPCs": len(data["Network"]["Vpcs"]),
            "EC2 Instances": len(data["Compute"]["Instances"]),
            "Load Balancers": len(data["Compute"]["LoadBalancersV2"]) + len(data["Compute"]["ClassicLoadBalancers"]),
            "ECS Clusters": len(data["Containers"]["EcsClusters"]),
            "EKS Clusters": len(data["Containers"]["EksClusters"]),
            "RDS Instances": len(data["DataStores"]["RdsInstances"]),
            "Lambda Functions": len(data["DataStores"]["LambdaFunctions"]),
        }
    return counts


# --------------------------------------------------------------------------
# Mermaid topology rendering
#
# Diagram contract (kept in sync with
# skills/aws-lucid-diagrams/references/diagram-conventions.md):
#   1. every edge is labelled with the actual connectivity -- destination
#      range, route table, protocol/port and direction, never a bare line;
#   2. abbreviations are expanded the first time they appear, in the node
#      label or the legend, so the diagram reads without AWS fluency;
#   3. labels stay short enough to render -- one fact per line, `<br/>` breaks;
#   4. every diagram ends with a legend inventorying the symbols it used and
#      what each one means.
# --------------------------------------------------------------------------

# node kind -> (opening, closing) Mermaid shape delimiters
_SHAPES = {
    "internet": ('(["', '"])'),
    "vpc": ('["', '"]'),
    "subnet": ('["', '"]'),
    "gateway": ('{{"', '"}}'),
    "endpoint": ('("', '")'),
}

# node kind -> (legend name, what the symbol means)
_LEGEND = {
    "internet": ("Public internet", "any address outside this account"),
    "vpc": (
        "Virtual Private Cloud (VPC)",
        "isolated private network; label shows its address range",
    ),
    "subnet": (
        "Subnet",
        "address range in one Availability Zone;<br/>Public = route to the Internet Gateway, "
        "Private = out through a NAT Gateway, Isolated = no default route",
    ),
    "gateway": (
        "Gateway",
        "Internet, NAT (Network Address Translation) or Transit Gateway;<br/>where packets leave a subnet",
    ),
    "endpoint": (
        "VPC endpoint",
        "private link to an AWS service; traffic stays on the AWS network",
    ),
}

_ARROW_LEGEND = (
    "Arrow = one connection.<br/>"
    "Label gives destination range, route table, protocol and direction.<br/>"
    "Two arrowheads = traffic flows both ways."
)


def _ident(value: str) -> str:
    """A Mermaid-safe node identifier from an AWS id, ARN, or region name."""
    return re.sub(r"[^0-9A-Za-z_]", "_", str(value))


def _text(value: str) -> str:
    """Label text that cannot break out of its quoted Mermaid label."""
    return str(value).replace('"', "'").replace("|", "/")


def _subnet_route_table(subnet: dict, route_tables: list[dict]) -> dict | None:
    """The route table that actually governs a subnet: its explicit
    association if it has one, otherwise the VPC's main table."""
    subnet_id = subnet.get("SubnetId")
    for rt in route_tables:
        if any(a.get("SubnetId") == subnet_id for a in rt.get("Associations", [])):
            return rt
    for rt in route_tables:
        if rt.get("VpcId") == subnet.get("VpcId") and any(
            a.get("Main") for a in rt.get("Associations", [])
        ):
            return rt
    return None


def _default_route(route_table: dict | None) -> dict:
    """The 0.0.0.0/0 (or ::/0) route, i.e. what makes a subnet public or not."""
    for route in (route_table or {}).get("Routes", []):
        if route.get("DestinationCidrBlock") == "0.0.0.0/0" or route.get("DestinationIpv6CidrBlock") == "::/0":
            return route
    return {}


def _subnet_connectivity(subnet: dict, route_tables: list[dict]) -> tuple[str, str, str]:
    """(role, default-route target id, edge label) for one subnet.

    `role` is Public/Private/Isolated as inferred from the default route, and
    the label spells out the route that justifies it -- that sentence is what
    ends up on the connector in the diagram.
    """
    rt = _subnet_route_table(subnet, route_tables)
    rtb = (rt or {}).get("RouteTableId") or "no route table"
    route = _default_route(rt)
    gateway = route.get("GatewayId") or ""
    nat = route.get("NatGatewayId") or ""
    tgw = route.get("TransitGatewayId") or ""
    if gateway.startswith("igw-"):
        return "Public", gateway, f"0.0.0.0/0 via {rtb}: any protocol, inbound and outbound"
    if nat:
        return "Private", nat, f"0.0.0.0/0 via {rtb}: outbound only, replies allowed"
    if tgw:
        return "Private", tgw, f"0.0.0.0/0 via {rtb}: private routing only, no internet"
    return "Isolated", "", f"no 0.0.0.0/0 route in {rtb}"


def _legend_lines(used: dict[str, int]) -> list[str]:
    """Legend subgraph inventorying only the symbols this diagram used."""
    if not used:
        return []
    lines = ['  subgraph Legend["Legend -- symbols on this diagram"]', "    direction TB"]
    for kind, (name, meaning) in _LEGEND.items():
        if kind not in used:
            continue
        open_, close = _SHAPES[kind]
        lines.append(f"    legend_{kind}{open_}{name} x{used[kind]} -- {meaning}{close}")
    lines.append(f'    legend_arrows["{_ARROW_LEGEND}"]')
    lines.append("  end")
    return lines


def vpc_topology_mermaid(region: str, network: dict) -> str:
    """Network topology for one region as a Mermaid flowchart.

    Every edge is labelled with how the two ends actually talk, and the
    diagram carries a legend describing each symbol it used.
    """
    route_tables = network.get("RouteTables", [])
    endpoints = network.get("VpcEndpoints", [])
    peerings = network.get("VpcPeeringConnections", [])
    tgw_attachments = network.get("TransitGatewayAttachments", [])
    vpc_ids = {v["VpcId"] for v in network.get("Vpcs", [])}

    prelude: list[str] = []
    body: list[str] = []
    tail: list[str] = []
    used: dict[str, int] = {}
    seen: set[str] = set()

    def node(node_id: str, kind: str, label: str, *, outside_region: bool = False) -> str:
        if node_id not in seen:
            seen.add(node_id)
            used[kind] = used.get(kind, 0) + 1
            open_, close = _SHAPES[kind]
            target, indent = (prelude, "    ") if outside_region else (body, "    ")
            target.append(f"{indent}{node_id}{open_}{_text(label)}{close}")
        return node_id

    def edge(src: str, dst: str, label: str, arrow: str = "-->", *, outside_region: bool = False) -> None:
        target, indent = (tail, "  ") if outside_region else (body, "    ")
        target.append(f'{indent}{src} {arrow}|"{_text(label)}"| {dst}')

    def internet_node() -> str:
        return node("internet", "internet", "Public internet<br/>0.0.0.0/0", outside_region=True)

    for vpc_record in network.get("Vpcs", []):
        vpc_id = vpc_record["VpcId"]
        vid = node(_ident(vpc_id), "vpc", f"Virtual Private Cloud {vpc_id}<br/>{vpc_record.get('CidrBlock', 'no address range')}")

        for igw in network.get("InternetGateways", []):
            if not any(a.get("VpcId") == vpc_id for a in igw.get("Attachments", [])):
                continue
            gid = node(_ident(igw["InternetGatewayId"]), "gateway", f"Internet Gateway<br/>{igw['InternetGatewayId']}")
            edge(internet_node(), gid, "public IPv4 and IPv6, any protocol", arrow="<-->")
            edge(gid, vid, f"attached to {vpc_id}: the VPC's only direct internet path")

        for nat in network.get("NatGateways", []):
            if nat.get("VpcId") != vpc_id:
                continue
            addresses = nat.get("NatGatewayAddresses") or [{}]
            public_ip = addresses[0].get("PublicIp") or "no public address"
            nid = node(
                _ident(nat["NatGatewayId"]),
                "gateway",
                f"NAT Gateway (Network Address Translation)<br/>{nat['NatGatewayId']} in "
                f"{nat.get('SubnetId', 'unknown subnet')}, public address {public_ip}",
            )
            for igw in network.get("InternetGateways", []):
                if any(a.get("VpcId") == vpc_id for a in igw.get("Attachments", [])):
                    edge(nid, _ident(igw["InternetGatewayId"]), f"egress translated to {public_ip}, replies only")

        for attachment in tgw_attachments:
            if attachment.get("ResourceId") != vpc_id:
                continue
            tgw_id = attachment.get("TransitGatewayId", "unknown transit gateway")
            tid = node(_ident(tgw_id), "gateway", f"Transit Gateway<br/>{tgw_id}")
            edge(
                vid,
                tid,
                f"attachment {attachment.get('TransitGatewayAttachmentId', 'unknown')}: "
                "private routing to other attached networks",
            )

        for subnet in network.get("Subnets", []):
            if subnet.get("VpcId") != vpc_id:
                continue
            role, target, route_label = _subnet_connectivity(subnet, route_tables)
            sid = node(
                _ident(subnet["SubnetId"]),
                "subnet",
                f"{role} subnet {subnet['SubnetId']}<br/>{subnet.get('CidrBlock', 'no address range')}"
                f" in {subnet.get('AvailabilityZone', 'unknown Availability Zone')}",
            )
            edge(vid, sid, f"allocates {subnet.get('CidrBlock', 'an address range')}")
            if target and _ident(target) in seen:
                edge(sid, _ident(target), route_label)

        for endpoint in endpoints:
            if endpoint.get("VpcId") != vpc_id:
                continue
            kind = endpoint.get("VpcEndpointType", "Interface")
            service = (endpoint.get("ServiceName") or "unknown service").split(".")[-1]
            eid = node(
                _ident(endpoint["VpcEndpointId"]),
                "endpoint",
                f"{kind} endpoint for {service}<br/>{endpoint['VpcEndpointId']}",
            )
            attached = [s for s in endpoint.get("SubnetIds", []) if _ident(s) in seen]
            if attached:
                for subnet_id in attached:
                    edge(_ident(subnet_id), eid, f"HTTPS 443 to {service} over a private address")
            else:
                edge(vid, eid, f"route table entry for {service}: private path, never leaves AWS")

    for peering in peerings:
        requester = (peering.get("RequesterVpcInfo") or {}).get("VpcId")
        accepter = (peering.get("AccepterVpcInfo") or {}).get("VpcId")
        if not requester or not accepter:
            continue
        for info in (peering.get("RequesterVpcInfo") or {}, peering.get("AccepterVpcInfo") or {}):
            # A peer in another region or account is not in this inventory --
            # draw it anyway so the connection has a visible far end.
            if info.get("VpcId") not in vpc_ids:
                node(
                    _ident(info.get("VpcId")),
                    "vpc",
                    f"Peered VPC {info.get('VpcId')}<br/>{info.get('CidrBlock', 'range not reported')} in "
                    f"account {info.get('OwnerId', 'unknown')}",
                    outside_region=True,
                )
        pcx = peering.get("VpcPeeringConnectionId", "peering connection")
        # Drawn after the region subgraph closes: a peering can cross into
        # another region or account, so it is not a relationship inside this
        # region's box.
        edge(
            _ident(requester),
            _ident(accepter),
            f"{pcx}: private IPv4 between the two ranges, not transitive",
            arrow="<-->",
            outside_region=True,
        )

    lines = ["flowchart TB"]
    if prelude:
        # Everything that is not part of this region -- the public internet,
        # a peer VPC in another region or account -- gets its own box, so the
        # layout engine cannot draw it inside the region's boundary.
        lines.append('  subgraph External["Outside this region"]')
        lines.extend(prelude)
        lines.append("  end")
    lines.append(f'  subgraph Region_{_ident(region)}["Region {region}"]')
    lines.extend(body)
    lines.append("  end")
    lines.extend(tail)
    lines.extend(_legend_lines(used))
    return "\n".join(lines)


def build_report(inventory: dict, region_counts: dict[str, dict[str, int]]) -> Report:
    report = Report(
        title="AWS Architecture Discovery",
        subtitle="Infrastructure inventory across VPC, compute, container, and data-store services",
        meta={"Account": inventory.get("AccountId") or "unknown", "Regions scanned": ", ".join(region_counts)},
    )

    categories = list(region_counts)
    series = {}
    for region in categories:
        for resource, count in region_counts[region].items():
            series.setdefault(resource, []).append(count)
    if categories:
        chart_uri = charts.grouped_bar_chart(categories, series, title="Resource counts by region", ylabel="Count")
        report.add_section("Resource Inventory Summary", f"![Resource counts]({chart_uri})")

    for region, data in inventory["Regions"].items():
        network = data["Network"]
        body = []
        counts = region_counts[region]
        body.append(
            findings_table(
                [{"Resource": k, "Count": v} for k, v in counts.items()], ["Resource", "Count"]
            )
        )
        if network["WideOpenSecurityGroupRules"]:
            body.append(f"\n**{len(network['WideOpenSecurityGroupRules'])} security group rule(s) open to 0.0.0.0/0 or ::/0** -- see `aws-security-review` for a full posture assessment.")
        if network["Vpcs"]:
            body.append("\n```mermaid\n" + vpc_topology_mermaid(region, network) + "\n```")
            body.append(
                "\n_Mermaid diagram renders in GitHub, VS Code, and Markdown-aware viewers/Artifacts; "
                "the HTML/PDF export below shows it as source text._"
            )
        report.add_section(f"Region: {region}", "\n".join(body))

    global_ds = inventory["Global"]["DataStores"]
    global_body = [
        f"- **S3 buckets:** {len(global_ds['S3Buckets'])}",
        f"- **Publicly accessible buckets:** {len(global_ds['PubliclyAccessibleBuckets'])}",
        f"- **Unencrypted buckets:** {len(global_ds['UnencryptedBuckets'])}",
    ]
    report.add_section("Global Resources (S3)", "\n".join(global_body))
    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    regions = resolve_regions(ctx, args)

    inventory = collect(ctx, regions)
    region_counts = resource_counts_by_region(inventory)

    if args.json_out:
        jsonutil.write(inventory, args.json_out)
        print(f"Raw inventory JSON written to {args.json_out}")

    report = build_report(inventory, region_counts)
    paths = report.save(args.output_dir, "architecture-discovery", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
