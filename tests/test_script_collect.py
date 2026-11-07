"""Tests for each skill script's `collect()` orchestration.

test_script_main.py stubs `collect()` whole, and test_collectors_*.py
tests the individual collector functions -- which leaves the wiring
*inside* each `collect()` unguarded: which collector runs per region vs.
once globally, and under which evidence key its result lands. A renamed
key here breaks the matching `build_report()` (and the JSON contract the
gap-analysis skill reads) while every other test stays green.

Each test monkeypatches the collector functions the script imports and
asserts the assembled evidence shape; no AWS calls, no moto.
"""
from __future__ import annotations

import datetime
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


discover = _load("collect_discover", "skills/aws-architecture-discovery/scripts/discover.py")
analyze_cost = _load("collect_analyze_cost", "skills/aws-cost-optimization/scripts/analyze_cost.py")
security_scan = _load("collect_security_scan", "skills/aws-security-review/scripts/security_scan.py")
traffic_analysis = _load("collect_traffic_analysis", "skills/aws-network-traffic-analysis/scripts/traffic_analysis.py")
collect_evidence = _load("collect_collect_evidence", "skills/aws-well-architected-review/scripts/collect_evidence.py")
dr_readiness = _load("collect_dr_readiness", "skills/aws-dr-readiness/scripts/dr_readiness.py")


class _Ctx:
    """Stand-in AwsContext: collect() only passes it through to collectors."""

    def account_id(self):
        return "123456789012"


def _tag(name):
    """A fake collector that records which (ctx-free) args it was called
    with inside its return value, so key wiring and per-region fan-out are
    both visible in the assembled dict."""

    def fake(ctx, *args, **kwargs):
        return {"collector": name, "args": args, "kwargs": kwargs}

    return fake


def test_discover_collect_fans_out_per_region_and_collects_s3_once(monkeypatch):
    monkeypatch.setattr(discover.vpc, "collect_region_network", _tag("network"))
    monkeypatch.setattr(discover.compute, "collect_region_compute", _tag("compute"))
    monkeypatch.setattr(discover.containers, "collect_region_containers", _tag("containers"))
    monkeypatch.setattr(discover.data_stores, "collect_region_data_stores", _tag("data_stores"))
    monkeypatch.setattr(discover.data_stores, "collect_global_data_stores", _tag("global_data_stores"))

    inventory = discover.collect(_Ctx(), ["us-east-1", "eu-west-1"])

    assert inventory["AccountId"] == "123456789012"
    assert set(inventory["Regions"]) == {"us-east-1", "eu-west-1"}
    for region in ("us-east-1", "eu-west-1"):
        region_data = inventory["Regions"][region]
        assert set(region_data) == {"Network", "Compute", "Containers", "DataStores"}
        assert region_data["Network"] == {"collector": "network", "args": (region,), "kwargs": {}}
    assert inventory["Global"]["DataStores"]["collector"] == "global_data_stores"


def test_discover_collect_tolerates_account_id_failure(monkeypatch):
    """The account ID is a report label, not evidence -- an identity call
    failure must not abort discovery."""
    from botocore.exceptions import ClientError

    class NoStsCtx(_Ctx):
        def account_id(self):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetCallerIdentity")

    for module, name in (
        (discover.vpc, "collect_region_network"),
        (discover.compute, "collect_region_compute"),
        (discover.containers, "collect_region_containers"),
        (discover.data_stores, "collect_region_data_stores"),
        (discover.data_stores, "collect_global_data_stores"),
    ):
        monkeypatch.setattr(module, name, _tag(name))

    inventory = discover.collect(NoStsCtx(), ["us-east-1"])
    assert inventory["AccountId"] is None
    assert "us-east-1" in inventory["Regions"]


def test_security_scan_collect_wires_global_and_regional_evidence(monkeypatch):
    monkeypatch.setattr(security_scan.security, "collect_global_security", _tag("global_security"))
    monkeypatch.setattr(security_scan.security, "collect_region_security", _tag("region_security"))
    monkeypatch.setattr(security_scan.security, "account_public_access_block", _tag("account_bpa"))
    monkeypatch.setattr(security_scan.compute, "collect_region_compute", _tag("compute"))
    monkeypatch.setattr(security_scan.data_stores, "collect_global_data_stores", _tag("global_data_stores"))
    monkeypatch.setattr(security_scan.data_stores, "describe_rds_instances", lambda ctx, region: [{"DBInstanceIdentifier": f"db-{region}"}])
    monkeypatch.setattr(security_scan.data_stores, "describe_rds_snapshots", lambda ctx, region: [{"DBSnapshotIdentifier": f"snap-{region}"}])
    monkeypatch.setattr(security_scan.data_stores, "rds_exposure", lambda instances: {"PubliclyAccessible": instances, "Unencrypted": []})
    monkeypatch.setattr(security_scan.data_stores, "public_rds_snapshots", lambda ctx, region, snaps: [{"Public": snaps[0]["DBSnapshotIdentifier"]}])
    monkeypatch.setattr(security_scan.data_stores, "public_rds_cluster_snapshots", lambda ctx, region: [{"PublicCluster": f"csnap-{region}"}])
    monkeypatch.setattr(security_scan.cloudtrail, "cloudtrail_posture", _tag("cloudtrail"))
    monkeypatch.setattr(security_scan.vpc, "describe_security_groups", lambda ctx, region: [{"GroupId": f"sg-{region}"}])
    monkeypatch.setattr(security_scan.vpc, "wide_open_security_groups", lambda sgs: [{"Open": sgs[0]["GroupId"]}])
    monkeypatch.setattr(security_scan.vpc, "default_security_groups_with_rules", lambda sgs: [{"Default": sgs[0]["GroupId"]}])

    data = security_scan.collect(_Ctx(), ["us-east-1", "eu-west-1"])

    assert set(data["Regions"]) == {"us-east-1", "eu-west-1"}
    # Both SG analyzers must see the same single describe_security_groups call.
    assert data["Regions"]["eu-west-1"]["WideOpenSecurityGroups"] == [{"Open": "sg-eu-west-1"}]
    assert data["Regions"]["eu-west-1"]["DefaultSecurityGroupsWithRules"] == [{"Default": "sg-eu-west-1"}]
    assert data["Regions"]["eu-west-1"]["Security"]["args"] == ("eu-west-1",)
    # RDS exposure is derived from that region's own instance/snapshot lists.
    assert data["Regions"]["eu-west-1"]["RdsExposure"]["PubliclyAccessible"] == [{"DBInstanceIdentifier": "db-eu-west-1"}]
    # DB snapshots and Aurora/Multi-AZ cluster snapshots land in one list.
    assert data["Regions"]["eu-west-1"]["PublicRdsSnapshots"] == [
        {"Public": "snap-eu-west-1"},
        {"PublicCluster": "csnap-eu-west-1"},
    ]
    assert data["Global"]["collector"] == "global_security"
    # CloudTrail trails are account-wide: exactly one call, from the first region.
    assert data["Global"]["CloudTrail"]["args"] == ("us-east-1",)
    assert data["Global"]["DataStores"]["collector"] == "global_data_stores"
    assert data["Global"]["AccountPublicAccessBlock"]["collector"] == "account_bpa"


def test_analyze_cost_collect_queries_compute_optimizer_and_idle_per_region(monkeypatch):
    monkeypatch.setattr(analyze_cost.cost, "collect_cost_report", _tag("cost_report"))
    monkeypatch.setattr(analyze_cost.cost, "compute_optimizer_ec2_recommendations", _tag("co_ec2"))
    monkeypatch.setattr(analyze_cost.cost, "compute_optimizer_ebs_recommendations", _tag("co_ebs"))
    monkeypatch.setattr(analyze_cost.compute, "describe_volumes", lambda ctx, region: [])
    monkeypatch.setattr(analyze_cost.compute, "describe_addresses", lambda ctx, region: [])
    monkeypatch.setattr(analyze_cost.compute, "describe_instances", lambda ctx, region: [])
    monkeypatch.setattr(analyze_cost.compute, "unattached_volumes", lambda vols: ["vol"])
    monkeypatch.setattr(analyze_cost.compute, "unassociated_eips", lambda addrs: ["eip"])
    monkeypatch.setattr(analyze_cost.compute, "idle_instance_candidates", lambda insts: ["inst"])

    data = analyze_cost.collect(_Ctx(), "2024-01-01", "2024-03-01", ["us-east-1", "eu-west-1"])

    assert data["CostReport"]["args"] == ("2024-01-01", "2024-03-01")
    assert set(data["ComputeOptimizerEc2"]) == {"us-east-1", "eu-west-1"}
    assert data["ComputeOptimizerEbs"]["eu-west-1"]["args"] == ("eu-west-1",)
    assert data["IdleResources"]["us-east-1"] == {
        "UnattachedVolumes": ["vol"],
        "UnassociatedEips": ["eip"],
        "StoppedInstances": ["inst"],
    }


def test_traffic_analysis_collect_builds_a_utc_window_in_epoch_seconds(monkeypatch):
    captured = {}

    def fake_analyze(ctx, region, log_group, start_epoch, end_epoch):
        captured.update(region=region, log_group=log_group, start=start_epoch, end=end_epoch)
        return {"queries": "ok"}

    monkeypatch.setattr(traffic_analysis.nt, "analyze_flow_logs", fake_analyze)
    monkeypatch.setattr(traffic_analysis.nt, "network_findings", _tag("findings"))

    data = traffic_analysis.collect(_Ctx(), "us-east-1", "/vpc/fl", lookback_hours=6)

    assert data["FlowLogAnalysis"] == {"queries": "ok"}
    assert data["NetworkFindings"]["args"] == ("us-east-1",)
    assert captured["log_group"] == "/vpc/fl"
    assert isinstance(captured["start"], int) and isinstance(captured["end"], int)
    assert captured["end"] - captured["start"] == 6 * 3600
    # The window is stated in the report; it must be the queried one.
    window_start = datetime.datetime.fromisoformat(data["Window"]["Start"])
    assert int(window_start.timestamp()) == captured["start"]
    assert window_start.tzinfo is not None, "window must be timezone-aware UTC, not local time"


def test_dr_readiness_collect_merges_backup_and_builds_summary(monkeypatch):
    def fake_backup(ctx, region):
        return {
            "BackupPlans": [f"plan-{region}"],
            "BackupVaults": [f"vault-{region}"],
            "PlansWithCrossRegionCopy": [],
            "FailedJobsRecent": [f"job-{region}"],
            "ProtectedResources": [],
        }

    def fake_region_data_stores(ctx, region):
        return {
            "RdsInstances": [{"DBInstanceIdentifier": f"db-{region}", "MultiAZ": region == "eu-west-1"}],
            "RdsClusters": [],
        }

    monkeypatch.setattr(dr_readiness.backup, "collect_region_backup", fake_backup)
    monkeypatch.setattr(dr_readiness.data_stores, "collect_region_data_stores", fake_region_data_stores)
    monkeypatch.setattr(
        dr_readiness.data_stores, "collect_global_data_stores", lambda ctx: {"S3Buckets": [{"Name": "b", "_Replication": None}]}
    )
    monkeypatch.setattr(dr_readiness.dr, "list_health_checks", lambda ctx: [{"Id": "hc-1"}])
    monkeypatch.setattr(dr_readiness.dr, "list_hosted_zones", lambda ctx: [{"Name": "example.com."}])

    data = dr_readiness.collect(_Ctx(), ["us-east-1", "eu-west-1"])

    # The summary must aggregate across BOTH regions, not just the last one.
    assert data["Summary"]["Backup"]["PlanCount"] == 2
    assert data["Summary"]["Backup"]["RecentFailedJobs"] == 2
    single_az = [i["DBInstanceIdentifier"] for i in data["Summary"]["Rds"]["SingleAzInstances"]]
    assert single_az == ["db-us-east-1"]
    assert data["Summary"]["S3"]["UnreplicatedBuckets"] == [{"Name": "b", "_Replication": None}]
    assert data["Summary"]["Route53HealthChecks"] == [{"Id": "hc-1"}]
    assert data["Global"]["Route53HostedZones"] == [{"Name": "example.com."}]


def test_dr_merge_backup_concatenates_every_key_across_regions():
    merged = dr_readiness._merge_backup(
        {
            "us-east-1": {"Backup": {"BackupPlans": ["a"], "BackupVaults": [], "PlansWithCrossRegionCopy": ["x"], "FailedJobsRecent": [], "ProtectedResources": ["r1"]}},
            "eu-west-1": {"Backup": {"BackupPlans": ["b"], "BackupVaults": ["v"], "PlansWithCrossRegionCopy": [], "FailedJobsRecent": [], "ProtectedResources": ["r2"]}},
        }
    )
    assert merged["BackupPlans"] == ["a", "b"]
    assert merged["BackupVaults"] == ["v"]
    assert merged["PlansWithCrossRegionCopy"] == ["x"]
    assert merged["ProtectedResources"] == ["r1", "r2"]


def _fake_wa_collectors(monkeypatch):
    for module, name in (
        (collect_evidence.vpc, "collect_region_network"),
        (collect_evidence.compute, "collect_region_compute"),
        (collect_evidence.containers, "collect_region_containers"),
        (collect_evidence.data_stores, "collect_region_data_stores"),
        (collect_evidence.security, "collect_region_security"),
        (collect_evidence.backup, "collect_region_backup"),
        (collect_evidence.observability, "collect_region_observability"),
        (collect_evidence.security, "collect_global_security"),
        (collect_evidence.data_stores, "collect_global_data_stores"),
        (collect_evidence.cloudtrail, "cloudtrail_posture"),
    ):
        monkeypatch.setattr(module, name, _tag(name))
    monkeypatch.setattr(collect_evidence.quotas, "common_quota_values", _tag("quotas"))
    monkeypatch.setattr(collect_evidence.cost, "collect_cost_report", _tag("cost"))
    monkeypatch.setattr(collect_evidence.well_architected, "collect_workload_snapshot", _tag("workload"))


def test_collect_evidence_assembles_every_pillar_input(monkeypatch):
    _fake_wa_collectors(monkeypatch)

    evidence = collect_evidence.collect(_Ctx(), ["us-east-1"], workload_id=None)

    region = evidence["Regions"]["us-east-1"]
    assert set(region) == {"Network", "Compute", "Containers", "DataStores", "Security", "Backup", "Observability", "Quotas"}
    assert set(evidence["Global"]) == {"Security", "DataStores", "Cost", "CloudTrail"}
    assert evidence["Global"]["CloudTrail"]["args"] == ("us-east-1",)
    assert "Workload" not in evidence, "no WA Tool snapshot without --workload-id"


def test_collect_evidence_cross_references_workload_only_when_asked(monkeypatch):
    _fake_wa_collectors(monkeypatch)

    evidence = collect_evidence.collect(_Ctx(), ["eu-west-1"], workload_id="w" * 32)

    assert evidence["Workload"]["collector"] == "workload"
    assert evidence["Workload"]["args"] == ("eu-west-1", "w" * 32)
