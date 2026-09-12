"""Tests for each skill's CLI script report-building logic, using synthetic
evidence dicts (no AWS calls) -- collection functions themselves are already
covered against moto/Stubber in tests/test_collectors_*.py. These tests
guard the report-assembly layer: chart wiring, table construction, and that
every report still renders to Markdown/HTML/valid PDF bytes.
"""
from __future__ import annotations

import importlib.util
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
