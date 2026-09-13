"""Tests for each skill's CLI script report-building logic, using synthetic
evidence dicts (no AWS calls) -- collection functions themselves are already
covered against moto/Stubber in tests/test_collectors_*.py. These tests
guard the report-assembly layer: chart wiring, table construction, and that
every report still renders to Markdown/HTML/valid PDF bytes.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(module_name: str, script_path: str):
    path = ROOT / script_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


discover = _load("discover", "skills/aws-architecture-discovery/scripts/discover.py")
analyze_cost = _load("analyze_cost", "skills/aws-cost-optimization/scripts/analyze_cost.py")
security_scan = _load("security_scan", "skills/aws-security-review/scripts/security_scan.py")
traffic_analysis = _load("traffic_analysis", "skills/aws-network-traffic-analysis/scripts/traffic_analysis.py")
collect_evidence = _load("collect_evidence", "skills/aws-well-architected-review/scripts/collect_evidence.py")
analyze_organization = _load("analyze_organization", "skills/aws-organizations-posture/scripts/analyze_organization.py")
dr_readiness = _load("dr_readiness", "skills/aws-dr-readiness/scripts/dr_readiness.py")


def _assert_renders(report):
    md = report.render_markdown()
    assert len(md) > 0
    html = report.render_html()
    assert "<html" in html
    pdf = report.render_pdf_bytes()
    assert pdf[:4] == b"%PDF"
    return md


# ------------------------------------------------------- aws-architecture-discovery
def test_discover_build_report():
    inventory = {
        "AccountId": "123456789012",
        "Regions": {
            "us-east-1": {
                "Network": {
                    "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
                    "Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}],
                    "InternetGateways": [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}]}],
                    "NatGateways": [],
                    "WideOpenSecurityGroupRules": [{"GroupId": "sg-1"}],
                },
                "Compute": {"Instances": [{}], "LoadBalancersV2": [], "ClassicLoadBalancers": []},
                "Containers": {"EcsClusters": [], "EksClusters": []},
                "DataStores": {"RdsInstances": [], "LambdaFunctions": [{}]},
            }
        },
        "Global": {"DataStores": {"S3Buckets": [{"Name": "a"}], "PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []}},
    }
    counts = discover.resource_counts_by_region(inventory)
    assert counts["us-east-1"]["EC2 Instances"] == 1

    report = discover.build_report(inventory, counts)
    md = _assert_renders(report)
    assert "mermaid" in md
    assert "security group rule" in md.lower()


def test_vpc_topology_mermaid_empty_vpc_no_crash():
    """A VPC with zero subnets/gateways must still produce a valid Mermaid
    block (just the VPC node), not crash or emit malformed syntax."""
    network = {
        "Vpcs": [{"VpcId": "vpc-empty", "CidrBlock": "10.1.0.0/16"}],
        "Subnets": [],
        "InternetGateways": [],
        "NatGateways": [],
    }
    diagram = discover.vpc_topology_mermaid("us-east-1", network)
    assert "flowchart TB" in diagram
    assert "vpc_empty" in diagram


def test_vpc_topology_mermaid_no_vpcs_at_all_no_crash():
    network = {"Vpcs": [], "Subnets": [], "InternetGateways": [], "NatGateways": []}
    diagram = discover.vpc_topology_mermaid("us-east-1", network)
    assert "flowchart TB" in diagram
    assert "end" in diagram


def test_resource_counts_by_region_empty_regions_returns_empty_dict():
    assert discover.resource_counts_by_region({"Regions": {}}) == {}


def test_discover_build_report_handles_zero_regions_scanned():
    """A region with genuinely nothing in it (or --regions matching zero
    actual regions) must still produce a valid report, not crash on an
    empty categories list feeding the grouped-bar chart."""
    inventory = {
        "AccountId": "123456789012",
        "Regions": {},
        "Global": {"DataStores": {"S3Buckets": [], "PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []}},
    }
    counts = discover.resource_counts_by_region(inventory)
    report = discover.build_report(inventory, counts)
    md = _assert_renders(report)
    assert "Global Resources" in md


# The diagram contract these tests pin down is documented in
# skills/aws-lucid-diagrams/references/diagram-conventions.md: every edge
# labelled with real connectivity, abbreviations expanded, one clause per
# label, and a legend inventorying the symbols used.
FULL_NETWORK = {
    "Vpcs": [{"VpcId": "vpc-aaa", "CidrBlock": "10.0.0.0/16"}],
    "Subnets": [
        {"SubnetId": "subnet-pub", "VpcId": "vpc-aaa", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "us-east-1a"},
        {"SubnetId": "subnet-priv", "VpcId": "vpc-aaa", "CidrBlock": "10.0.2.0/24", "AvailabilityZone": "us-east-1a"},
        {"SubnetId": "subnet-iso", "VpcId": "vpc-aaa", "CidrBlock": "10.0.3.0/24", "AvailabilityZone": "us-east-1b"},
    ],
    "RouteTables": [
        {
            "RouteTableId": "rtb-pub",
            "VpcId": "vpc-aaa",
            "Associations": [{"SubnetId": "subnet-pub"}],
            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
        },
        {
            "RouteTableId": "rtb-priv",
            "VpcId": "vpc-aaa",
            "Associations": [{"SubnetId": "subnet-priv"}],
            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}],
        },
        {
            "RouteTableId": "rtb-main",
            "VpcId": "vpc-aaa",
            "Associations": [{"Main": True}],
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
        },
    ],
    "InternetGateways": [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-aaa"}]}],
    "NatGateways": [
        {
            "NatGatewayId": "nat-1",
            "VpcId": "vpc-aaa",
            "SubnetId": "subnet-pub",
            "NatGatewayAddresses": [{"PublicIp": "52.1.2.3"}],
        }
    ],
    "VpcEndpoints": [
        {
            "VpcEndpointId": "vpce-1",
            "VpcId": "vpc-aaa",
            "VpcEndpointType": "Interface",
            "ServiceName": "com.amazonaws.us-east-1.secretsmanager",
            "SubnetIds": ["subnet-priv"],
        },
        {
            "VpcEndpointId": "vpce-2",
            "VpcId": "vpc-aaa",
            "VpcEndpointType": "Gateway",
            "ServiceName": "com.amazonaws.us-east-1.s3",
            "RouteTableIds": ["rtb-priv"],
        },
    ],
    "VpcPeeringConnections": [
        {
            "VpcPeeringConnectionId": "pcx-9",
            "RequesterVpcInfo": {"VpcId": "vpc-aaa", "CidrBlock": "10.0.0.0/16", "OwnerId": "111122223333"},
            "AccepterVpcInfo": {"VpcId": "vpc-zzz", "CidrBlock": "10.9.0.0/16", "OwnerId": "444455556666"},
        }
    ],
    "TransitGatewayAttachments": [
        {"TransitGatewayAttachmentId": "tgw-attach-7", "TransitGatewayId": "tgw-7", "ResourceId": "vpc-aaa"}
    ],
}


def _edges(diagram: str) -> list[str]:
    return [ln.strip() for ln in diagram.splitlines() if "-->" in ln or ln.strip().startswith("---")]


def test_vpc_topology_labels_every_edge():
    """An unlabelled connector says only 'these are related', which the
    reader already assumed -- the generator must never emit one."""
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    edges = _edges(diagram)
    assert edges, "expected connectors in a fully-populated network"
    unlabelled = [e for e in edges if '|"' not in e]
    assert not unlabelled, f"connectors with no connectivity label: {unlabelled}"


def test_vpc_topology_edge_labels_carry_connectivity_detail():
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    # Routing: destination range + the route table that provides it.
    assert '0.0.0.0/0 via rtb-pub: any protocol, inbound and outbound' in diagram
    assert '0.0.0.0/0 via rtb-priv: outbound only, replies allowed' in diagram
    # Address translation, protocol/port, and cross-network attachments.
    assert "egress translated to 52.1.2.3" in diagram
    assert "HTTPS 443 to secretsmanager" in diagram
    assert "pcx-9" in diagram and "not transitive" in diagram
    assert "attachment tgw-attach-7" in diagram


def test_vpc_topology_classifies_subnets_from_route_tables():
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    assert "Public subnet subnet-pub" in diagram
    assert "Private subnet subnet-priv" in diagram
    # No default route in the main table it falls back to -> isolated.
    assert "Isolated subnet subnet-iso" in diagram


def test_vpc_topology_expands_abbreviations():
    """A reader without AWS fluency has to be able to follow the diagram."""
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    assert "Virtual Private Cloud vpc-aaa" in diagram
    assert "NAT Gateway (Network Address Translation)" in diagram
    assert "Availability Zone" in diagram or "us-east-1a" in diagram
    assert "IGW " not in diagram, "raw 'IGW' abbreviation leaked into a label"


def test_vpc_topology_legend_inventories_only_the_symbols_used():
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    legend = diagram.split("subgraph Legend")[1]
    assert "Subnet x3" in legend
    assert "Gateway x3" in legend  # internet gateway + NAT gateway + transit gateway
    assert "VPC endpoint x2" in legend
    assert "Virtual Private Cloud (VPC) x2" in legend  # local VPC + the peer
    assert "Public internet x1" in legend
    assert "Arrow = one connection." in legend


def test_vpc_topology_legend_omits_symbol_kinds_not_on_the_diagram():
    """A legend entry with no shape behind it is noise."""
    network = {"Vpcs": [{"VpcId": "vpc-bare", "CidrBlock": "10.0.0.0/16"}], "Subnets": [], "InternetGateways": [], "NatGateways": []}
    diagram = discover.vpc_topology_mermaid("us-east-1", network)
    legend = diagram.split("subgraph Legend")[1]
    assert "Virtual Private Cloud (VPC) x1" in legend
    for absent in ("Subnet x", "Gateway x", "VPC endpoint x", "Public internet x"):
        assert absent not in legend, f"legend lists {absent!r} but nothing on the diagram uses it"


def test_vpc_topology_no_legend_when_there_is_nothing_to_draw():
    diagram = discover.vpc_topology_mermaid("us-east-1", {"Vpcs": [], "Subnets": [], "InternetGateways": [], "NatGateways": []})
    assert "subgraph Legend" not in diagram


def test_vpc_topology_draws_the_far_end_of_a_cross_account_peering():
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    assert "Peered VPC vpc-zzz" in diagram
    assert "account 444455556666" in diagram
    # The peer is not in this region's inventory, so it belongs in the
    # "Outside this region" box, not inside the region's boundary.
    external = diagram.split('subgraph External')[1].split("\n  end")[0]
    assert "vpc_zzz[" in external
    assert "internet(" in external
    assert diagram.index("vpc_zzz[") < diagram.index("subgraph Region_us_east_1")


def test_vpc_topology_node_ids_are_mermaid_safe():
    network = {
        "Vpcs": [{"VpcId": "vpc-a.b", "CidrBlock": "10.0.0.0/16"}],
        "Subnets": [],
        "InternetGateways": [],
        "NatGateways": [],
    }
    diagram = discover.vpc_topology_mermaid("ap-southeast-2", network)
    node_line = [ln for ln in diagram.splitlines() if "Virtual Private Cloud" in ln][0]
    node_id = node_line.strip().split("[")[0]
    assert node_id == "vpc_a_b"


def test_vpc_topology_label_text_cannot_break_out_of_its_quotes():
    """AWS lets a tag/name carry a double quote or pipe; either would end
    the Mermaid label early and produce an unparseable diagram."""
    network = {
        "Vpcs": [{"VpcId": 'vpc-1', "CidrBlock": '10.0.0.0/16" | x'}],
        "Subnets": [],
        "InternetGateways": [],
        "NatGateways": [],
    }
    diagram = discover.vpc_topology_mermaid("us-east-1", network)
    label = diagram.split('vpc_1["')[1].split('"]')[0]
    assert '"' not in label and "|" not in label


def test_subnet_route_table_prefers_explicit_association_over_main():
    main = {"RouteTableId": "rtb-main", "VpcId": "vpc-1", "Associations": [{"Main": True}], "Routes": []}
    explicit = {
        "RouteTableId": "rtb-explicit",
        "VpcId": "vpc-1",
        "Associations": [{"SubnetId": "subnet-1"}],
        "Routes": [],
    }
    subnet = {"SubnetId": "subnet-1", "VpcId": "vpc-1"}
    assert discover._subnet_route_table(subnet, [main, explicit])["RouteTableId"] == "rtb-explicit"
    assert discover._subnet_route_table(subnet, [main])["RouteTableId"] == "rtb-main"
    assert discover._subnet_route_table(subnet, []) is None


def test_subnet_connectivity_reports_the_missing_route_table():
    """A subnet whose route table we can't find must say so on the diagram
    rather than silently looking isolated for the wrong reason."""
    role, target, label = discover._subnet_connectivity({"SubnetId": "subnet-x", "VpcId": "vpc-1"}, [])
    assert role == "Isolated"
    assert target == ""
    assert "no route table" in label


def test_subnet_connectivity_treats_an_ipv6_default_route_as_a_default_route():
    route_tables = [
        {
            "RouteTableId": "rtb-v6",
            "VpcId": "vpc-1",
            "Associations": [{"SubnetId": "subnet-1"}],
            "Routes": [{"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1"}],
        }
    ]
    role, target, _ = discover._subnet_connectivity({"SubnetId": "subnet-1", "VpcId": "vpc-1"}, route_tables)
    assert (role, target) == ("Public", "igw-1")


def test_vpc_topology_connects_a_subnet_routed_through_a_transit_gateway():
    """The Transit Gateway node has to exist before subnets are drawn, or a
    subnet whose default route points at it silently loses its edge."""
    network = {
        "Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
        "Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "us-east-1a"}],
        "RouteTables": [
            {
                "RouteTableId": "rtb-1",
                "VpcId": "vpc-1",
                "Associations": [{"SubnetId": "subnet-1"}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": "tgw-7"}],
            }
        ],
        "InternetGateways": [],
        "NatGateways": [],
        "TransitGatewayAttachments": [
            {"TransitGatewayAttachmentId": "tgw-attach-7", "TransitGatewayId": "tgw-7", "ResourceId": "vpc-1"}
        ],
    }
    diagram = discover.vpc_topology_mermaid("us-east-1", network)
    assert "subnet_1 -->|\"0.0.0.0/0 via rtb-1: private routing only, no internet\"| tgw_7" in diagram

def test_vpc_topology_is_structurally_valid_mermaid():
    """Cheap stand-in for a Mermaid parser: balanced subgraph/end pairs, no
    label with an odd number of quotes, and no edge pointing at a node that
    was never declared."""
    diagram = discover.vpc_topology_mermaid("us-east-1", FULL_NETWORK)
    lines = [ln.strip() for ln in diagram.splitlines()]
    assert lines[0] == "flowchart TB"
    assert sum(ln.startswith("subgraph ") for ln in lines) == sum(ln == "end" for ln in lines)
    for line in lines:
        assert line.count('"') % 2 == 0, f"unbalanced quotes: {line}"

    declared = {
        re.match(r"([A-Za-z0-9_]+)[\[({]", ln).group(1)
        for ln in lines
        if re.match(r"[A-Za-z0-9_]+[\[({]", ln) and "|" not in ln.split("[")[0]
    }
    assert declared, "no nodes parsed out of the diagram -- the check is vacuous"
    for line in lines:
        if "-->" not in line:
            continue
        src, dst = line.split(" ", 1)[0], line.rsplit("| ", 1)[-1]
        assert src in declared, f"edge source {src} never declared"
        assert dst in declared, f"edge target {dst} never declared"


def test_discover_report_embeds_the_legend_with_the_diagram():
    """The legend has to travel with the diagram into the rendered report --
    a diagram pasted elsewhere without it is unreadable."""
    inventory = {
        "AccountId": "123456789012",
        "Regions": {
            "us-east-1": {
                "Network": dict(FULL_NETWORK, WideOpenSecurityGroupRules=[]),
                "Compute": {"Instances": [], "LoadBalancersV2": [], "ClassicLoadBalancers": []},
                "Containers": {"EcsClusters": [], "EksClusters": []},
                "DataStores": {"RdsInstances": [], "LambdaFunctions": []},
            }
        },
        "Global": {"DataStores": {"S3Buckets": [], "PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []}},
    }
    md = discover.build_report(inventory, discover.resource_counts_by_region(inventory)).render_markdown()
    assert "```mermaid" in md
    assert "subgraph Legend" in md

# ------------------------------------------------------------- aws-cost-optimization
def test_cost_date_ranges_are_utc_not_local():
    """Regression test: both cost windows used `date.today()`, which returns
    the machine's LOCAL date. Cost Explorer interprets TimePeriod in UTC, so
    running from a timezone far enough east/west silently shifted the whole
    billing window by a day. Asserting against the UTC date proves the fix
    regardless of the runner's local timezone."""
    import datetime

    expected_end = datetime.datetime.now(datetime.timezone.utc).date()

    start, end = analyze_cost.date_range(90)
    assert end == expected_end.isoformat()
    assert start == (expected_end - datetime.timedelta(days=90)).isoformat()

    wa_start, wa_end = collect_evidence._default_cost_window()
    assert wa_end == expected_end.isoformat()
    assert wa_start == (expected_end - datetime.timedelta(days=90)).isoformat()


def test_analyze_cost_monthly_series_and_report():
    cost_by_service = [
        {"TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"}, "Groups": [
            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100.0"}}},
        ]},
        {"TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"}, "Groups": [
            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "120.0"}}},
        ]},
    ]
    months, series = analyze_cost.monthly_cost_series(cost_by_service)
    assert months == ["2024-01-01", "2024-02-01"]
    assert series["Amazon EC2"] == [100.0, 120.0]

    data = {
        "CostReport": {
            "CostByService": cost_by_service,
            "ReservationUtilization": {},
            "SavingsPlansUtilization": {},
            "RightsizingRecommendations": [],
            "TrustedAdvisorCostChecks": [],
            "Anomalies": [],
        },
        "ComputeOptimizerEc2": {"us-east-1": []},
        "ComputeOptimizerEbs": {"us-east-1": []},
        "IdleResources": {"us-east-1": {"UnattachedVolumes": [1, 2], "UnassociatedEips": [], "StoppedInstances": []}},
    }
    report = analyze_cost.build_report(data, "2024-01-01", "2024-03-01")
    md = _assert_renders(report)
    assert "Cost Trend" in md
    assert "Idle" in md


# -------------------------------------------------------------- aws-security-review
def test_security_scan_build_report_flags_open_sg_and_standards():
    data = {
        "Global": {
            "IamFindings": {"ConsoleUsersWithoutMfa": ["alice"], "AccessKeysToReview": [], "RootAccountRisks": [], "PasswordPolicySet": True},
            "DataStores": {"PubliclyAccessibleBuckets": [{"Name": "open"}], "UnencryptedBuckets": []},
            "CloudTrail": {"Trails": [], "HasMultiRegionTrail": False, "HasLoggingTrail": False, "HasLogFileValidation": False},
        },
        "Regions": {
            "us-east-1": {
                "Security": {
                    "GuardDuty": {"Enabled": True, "DetectorIds": ["d1"]},
                    "SecurityHub": {"Enabled": True},
                    "GuardDutyFindings": [{"Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 5.0}],
                    "SecurityHubFindings": [{"Severity": {"Label": "HIGH"}, "Title": "Exposed bucket", "Resources": [{"Id": "arn:aws:s3:::open"}]}],
                    "SecurityHubStandardsSummary": [
                        {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations/v/1.2.0", "ControlCount": 40, "EnabledControlCount": 35}
                    ],
                    "AccessAnalyzerFindings": [{"resourceType": "AWS::S3::Bucket", "status": "ACTIVE"}],
                    "ConfigRuleCompliance": [{"ConfigRuleName": "s3-public-read-prohibited", "Compliance": {"ComplianceType": "NON_COMPLIANT"}}],
                    "ConfigRecorder": {"Recording": False},
                },
                "WideOpenSecurityGroups": [{"GroupId": "sg-1", "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "OpenRanges": ["0.0.0.0/0"]}],
                "Compute": {
                    "InstancesAllowingImdsv1": [{"InstanceId": "i-1", "State": {"Name": "running"}}],
                    "PlaintextListeners": [{"LoadBalancerName": "web", "Port": 80, "Protocol": "HTTP"}],
                    "ExpiringCertificates": [{"DomainName": "example.com", "NotAfter": "2024-01-01", "InUse": True}],
                },
            }
        },
    }
    report = security_scan.build_report(data)
    md = _assert_renders(report)
    assert "Wide-Open Security Group" in md
    assert "cis-aws-foundations" in md
    assert "s3-public-read-prohibited" in md
    assert "NOT recording" in md
    assert "IMDSv2" in md
    assert "i-1" in md


def test_standard_name_parses_ruleset_arn():
    assert security_scan._standard_name(
        "arn:aws:securityhub:::ruleset/cis-aws-foundations/v/1.2.0"
    ) == "cis-aws-foundations v1.2.0"
    assert security_scan._standard_name("not-a-ruleset-arn") == "not-a-ruleset-arn"


# ------------------------------------------------------ aws-network-traffic-analysis
def test_traffic_analysis_build_report_flags_port_scan():
    data = {
        "Window": {"Start": "2024-01-01T00:00:00", "End": "2024-01-02T00:00:00"},
        "FlowLogAnalysis": {
            "top_talkers_by_bytes": [{"srcAddr": "10.0.0.5", "dstAddr": "10.0.0.9", "totalBytes": "12345"}],
            "traffic_by_protocol": [{"protocol": "6", "totalBytes": "999"}],
            "rejected_traffic": [{"srcAddr": "1.2.3.4", "dstAddr": "10.0.0.5", "dstPort": "22", "rejects": "40"}],
            "port_scan_candidates": [{"srcAddr": "1.2.3.4", "distinctPorts": "42"}],
            "top_external_egress": [{"srcAddr": "10.0.0.5", "dstAddr": "8.8.8.8", "totalBytes": "5000"}],
        },
        "NetworkFindings": [{"Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 5.0, "Resource": {"ResourceType": "Instance"}}],
    }
    report = traffic_analysis.build_report(data, "us-east-1", "/vpc/flowlogs")
    md = _assert_renders(report)
    assert "Possible Port Scan Activity" in md
    assert "Recon:EC2/PortProbeUnprotectedPort" in md


def test_traffic_analysis_no_findings_renders_clean_report():
    data = {
        "Window": {"Start": "2024-01-01T00:00:00", "End": "2024-01-02T00:00:00"},
        "FlowLogAnalysis": {
            "top_talkers_by_bytes": [],
            "traffic_by_protocol": [],
            "rejected_traffic": [],
            "port_scan_candidates": [],
            "top_external_egress": [],
        },
        "NetworkFindings": [],
    }
    report = traffic_analysis.build_report(data, "us-east-1", "/vpc/flowlogs")
    md = _assert_renders(report)
    assert "No rejected flows" in md
    assert "No source exceeded" in md
    # Regression test: Top Talkers/Protocol Mix/Top External Egress used to
    # be silently omitted when empty instead of stating so explicitly like
    # every other section -- the SKILL.md's own quality checks promise this.
    assert "No flow log records in this window." in md
    assert "No external egress observed in this window." in md


# ---------------------------------------------------------- aws-well-architected-review
def test_collect_evidence_build_report_covers_all_pillars():
    region_data = {
        "Network": {"WideOpenSecurityGroupRules": [], "NatGateways": [], "VpcEndpoints": []},
        "Compute": {
            "AutoScalingGroups": [], "LoadBalancersV2": [], "ClassicLoadBalancers": [],
            "UnattachedVolumes": [], "UnassociatedEips": [], "StoppedInstances": [], "Instances": [],
        },
        "Containers": {"EcsClusters": [], "EksClusters": []},
        "DataStores": {
            "LambdaFunctions": [], "RdsInstances": [], "RdsManualSnapshots": [],
            "ElastiCacheClusters": [], "DynamoDbTables": [],
        },
        "Security": {
            "GuardDuty": {"Enabled": True}, "SecurityHub": {"Enabled": True},
            "ConfigRuleCompliance": [], "AccessAnalyzerFindings": [], "ConfigRecorder": {"Recording": True},
        },
        "Backup": {"BackupPlans": [], "PlansWithCrossRegionCopy": [], "FailedJobsRecent": []},
        "Observability": {"Alarms": [], "AlarmsWithNoActions": [], "AlarmsInAlarmState": [], "Dashboards": []},
        "Quotas": [],
    }
    evidence = {
        "Regions": {"us-east-1": region_data},
        "Global": {
            "Security": {"IamFindings": {"ConsoleUsersWithoutMfa": [], "AccessKeysToReview": [], "RootAccountRisks": [], "PasswordPolicySet": True}},
            "DataStores": {},
            "Cost": {"Budgets": []},
            "CloudTrail": {"HasMultiRegionTrail": True, "HasLoggingTrail": True, "HasLogFileValidation": True},
        },
    }
    report = collect_evidence.build_report(evidence, list(collect_evidence.PILLARS))
    md = _assert_renders(report)
    for pillar in collect_evidence.PILLARS:
        assert pillar.replace("-", " ").title() in md


def test_collect_evidence_escapes_workload_name_from_wa_tool():
    """Regression test: WorkloadName is free text set by whoever created the
    Well-Architected Tool workload, and it lands in a section body (which
    Report does not escape, by contract) -- so this call site must escape
    it itself or the HTML report carries a stored-XSS payload."""
    payload = "<script>alert(1)</script>"
    region_data = {
        "Network": {"WideOpenSecurityGroupRules": [], "NatGateways": [], "VpcEndpoints": []},
        "Compute": {
            "AutoScalingGroups": [], "LoadBalancersV2": [], "ClassicLoadBalancers": [],
            "UnattachedVolumes": [], "UnassociatedEips": [], "StoppedInstances": [], "Instances": [],
            "InstancesAllowingImdsv1": [], "PlaintextListeners": [], "ExpiringCertificates": [],
        },
        "Containers": {"EcsClusters": [], "EksClusters": []},
        "DataStores": {
            "LambdaFunctions": [], "RdsInstances": [], "RdsManualSnapshots": [],
            "ElastiCacheClusters": [], "DynamoDbTables": [],
        },
        "Security": {
            "GuardDuty": {"Enabled": True}, "SecurityHub": {"Enabled": True},
            "ConfigRuleCompliance": [], "AccessAnalyzerFindings": [], "ConfigRecorder": {"Recording": True},
        },
        "Backup": {"BackupPlans": [], "PlansWithCrossRegionCopy": [], "FailedJobsRecent": []},
        "Observability": {"Alarms": [], "AlarmsWithNoActions": [], "AlarmsInAlarmState": [], "Dashboards": []},
        "Quotas": [],
    }
    evidence = {
        "Regions": {"us-east-1": region_data},
        "Global": {
            "Security": {"IamFindings": {"ConsoleUsersWithoutMfa": [], "AccessKeysToReview": [], "RootAccountRisks": [], "PasswordPolicySet": True}},
            "DataStores": {},
            "Cost": {"Budgets": []},
            "CloudTrail": {"HasMultiRegionTrail": True, "HasLoggingTrail": True, "HasLogFileValidation": True},
        },
        "Workload": {
            "Workload": {"WorkloadName": f"prod {payload}", "WorkloadId": "1" * 32},
            "ImprovementsByPillar": {"security": [{"x": 1}]},
        },
    }

    report = collect_evidence.build_report(evidence, ["security"])
    html_out = report.render_html()

    assert payload not in html_out
    assert "&lt;script&gt;" in html_out
    assert "Well-Architected Tool Cross-Reference" in report.render_markdown()


# --------------------------------------------------------- aws-organizations-posture
def test_analyze_organization_not_a_member_short_circuits():
    report = analyze_organization.build_report({"IsOrganizationsMember": False})
    md = _assert_renders(report)
    assert "not** part of an AWS Organization" in md


def test_analyze_organization_build_report_flags_uncovered_accounts_and_no_delegation():
    posture = {
        "IsOrganizationsMember": True,
        "Organization": {"MasterAccountId": "123456789012", "FeatureSet": "ALL"},
        "Accounts": [
            {"Id": "111111111111", "Name": "prod", "Email": "prod@example.com", "Status": "ACTIVE"},
            {"Id": "222222222222", "Name": "dev", "Email": "dev@example.com", "Status": "ACTIVE"},
        ],
        "ServiceControlPolicies": [
            {"Id": "p-1", "Name": "baseline", "Description": "baseline", "_Targets": [{"Type": "ACCOUNT", "TargetId": "111111111111"}]}
        ],
        "AccountsWithoutScpCoverage": [{"Id": "222222222222", "Name": "dev"}],
        "DelegatedAdministrators": [],
        "GuardDutyOrganizationAdmin": None,
        "SecurityHubOrganizationAdmin": {"AccountId": "111111111111"},
    }
    report = analyze_organization.build_report(posture)
    md = _assert_renders(report)
    assert "222222222222" in md
    assert "NOT configured" in md  # GuardDuty admin missing
    assert "111111111111" in md  # Security Hub admin present


# ------------------------------------------------------------------- aws-dr-readiness
def test_dr_readiness_build_report_flags_single_az_and_missing_health_checks():
    data = {
        "Summary": {
            "Backup": {"PlanCount": 1, "VaultCount": 1, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 3, "RecentFailedJobs": 1},
            "Rds": {
                "SingleAzInstances": [{"DBInstanceIdentifier": "db-1"}],
                "InstancesWithReadReplicas": [],
                "CrossRegionOrGlobalClusters": [],
            },
            "S3": {"ReplicatedBuckets": [], "UnreplicatedBuckets": [{"Name": "a"}]},
            "Route53HealthChecks": [],
        }
    }
    report = dr_readiness.build_report(data)
    md = _assert_renders(report)
    assert "db-1" in md
    assert "No Route 53 health checks configured" in md


def test_dr_readiness_build_report_with_health_checks_and_replication():
    data = {
        "Summary": {
            "Backup": {"PlanCount": 2, "VaultCount": 2, "PlansWithCrossRegionCopy": 1, "ProtectedResourceCount": 10, "RecentFailedJobs": 0},
            "Rds": {
                "SingleAzInstances": [],
                "InstancesWithReadReplicas": [{"DBInstanceIdentifier": "db-2"}],
                "CrossRegionOrGlobalClusters": [{"DBClusterIdentifier": "c-1"}],
            },
            "S3": {"ReplicatedBuckets": [{"Name": "a"}], "UnreplicatedBuckets": []},
            "Route53HealthChecks": [
                {"Id": "hc-1", "HealthCheckConfig": {"Type": "HTTPS", "FullyQualifiedDomainName": "example.com"}}
            ],
        }
    }
    report = dr_readiness.build_report(data)
    md = _assert_renders(report)
    assert "hc-1" in md
    assert "example.com" in md


def test_dr_readiness_build_report_includes_hosted_zone_count():
    data = {
        "Summary": {
            "Backup": {"PlanCount": 0, "VaultCount": 0, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 0, "RecentFailedJobs": 0},
            "Rds": {"SingleAzInstances": [], "InstancesWithReadReplicas": [], "CrossRegionOrGlobalClusters": []},
            "S3": {"ReplicatedBuckets": [], "UnreplicatedBuckets": []},
            "Route53HealthChecks": [],
        },
        "Global": {"Route53HostedZones": [{"Name": "example.com."}, {"Name": "other.com."}]},
    }
    report = dr_readiness.build_report(data)
    md = _assert_renders(report)
    assert "**2** hosted zone(s)" in md


def test_dr_readiness_build_report_no_hosted_zones_states_gap():
    data = {
        "Summary": {
            "Backup": {"PlanCount": 0, "VaultCount": 0, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 0, "RecentFailedJobs": 0},
            "Rds": {"SingleAzInstances": [], "InstancesWithReadReplicas": [], "CrossRegionOrGlobalClusters": []},
            "S3": {"ReplicatedBuckets": [], "UnreplicatedBuckets": []},
            "Route53HealthChecks": [],
        },
    }
    report = dr_readiness.build_report(data)
    md = _assert_renders(report)
    assert "No Route 53 hosted zones found" in md
