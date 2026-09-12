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


def vpc_topology_mermaid(region: str, network: dict) -> str:
    lines = ["flowchart TB", f"  subgraph Region_{region.replace('-', '_')}[\"{region}\"]"]
    for v in network["Vpcs"]:
        vid = v["VpcId"].replace("-", "_")
        lines.append(f"    {vid}[\"VPC {v['VpcId']}\\n{v.get('CidrBlock', '')}\"]")
        for igw in network["InternetGateways"]:
            if any(a.get("VpcId") == v["VpcId"] for a in igw.get("Attachments", [])):
                igw_id = igw["InternetGatewayId"].replace("-", "_")
                lines.append(f"    {igw_id}((\"IGW {igw['InternetGatewayId']}\"))")
                lines.append(f"    {igw_id} --- {vid}")
        for nat in network["NatGateways"]:
            if nat.get("VpcId") == v["VpcId"]:
                nat_id = nat["NatGatewayId"].replace("-", "_")
                lines.append(f"    {nat_id}[\"NAT {nat['NatGatewayId']}\"]")
                lines.append(f"    {vid} --- {nat_id}")
        for subnet in network["Subnets"]:
            if subnet.get("VpcId") == v["VpcId"]:
                sid = subnet["SubnetId"].replace("-", "_")
                lines.append(f"    {sid}[\"Subnet {subnet['SubnetId']}\\n{subnet.get('CidrBlock', '')}\"]")
                lines.append(f"    {vid} --> {sid}")
    lines.append("  end")
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
