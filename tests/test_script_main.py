"""End-to-end tests for each skill script's `main()` entry point.

The other script tests (test_skill_scripts.py) call `build_report()`
directly with synthetic data. That leaves the top-level wiring untested:
argparse flags, the collect->build_report handoff, `--json-out`, the
`report.save()` call and its hardcoded basename, and the process exit
code. A regression there (a renamed flag, a broken save call, a
build_report signature change) would pass every other test and still
break the skill for a real user.

These tests stub ONLY `collect()` -- the single AWS-touching function in
each script -- and let everything else run for real, writing actual
files to a tmp_path.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(module_name: str, script_path: str):
    path = ROOT / script_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


discover = _load("main_discover", "skills/aws-architecture-discovery/scripts/discover.py")
analyze_cost = _load("main_analyze_cost", "skills/aws-cost-optimization/scripts/analyze_cost.py")
security_scan = _load("main_security_scan", "skills/aws-security-review/scripts/security_scan.py")
traffic_analysis = _load("main_traffic_analysis", "skills/aws-network-traffic-analysis/scripts/traffic_analysis.py")
collect_evidence = _load("main_collect_evidence", "skills/aws-well-architected-review/scripts/collect_evidence.py")
analyze_organization = _load("main_analyze_organization", "skills/aws-organizations-posture/scripts/analyze_organization.py")
dr_readiness = _load("main_dr_readiness", "skills/aws-dr-readiness/scripts/dr_readiness.py")


# --------------------------------------------------------------- fixtures
def _empty_region_evidence() -> dict:
    """A region with every collector key present but empty -- the shape
    build_report()s must tolerate."""
    return {
        "Network": {
            "Vpcs": [], "Subnets": [], "InternetGateways": [], "NatGateways": [],
            "VpcEndpoints": [], "WideOpenSecurityGroupRules": [],
        },
        "Compute": {
            "Instances": [], "AutoScalingGroups": [], "LoadBalancersV2": [],
            "ClassicLoadBalancers": [], "UnattachedVolumes": [], "UnassociatedEips": [],
            "StoppedInstances": [], "InstancesAllowingImdsv1": [], "PlaintextListeners": [],
            "ExpiringCertificates": [],
        },
        "Containers": {"EcsClusters": [], "EksClusters": []},
        "DataStores": {
            "RdsInstances": [], "RdsClusters": [], "RdsManualSnapshots": [],
            "DynamoDbTables": [], "ElastiCacheClusters": [], "LambdaFunctions": [],
        },
        "Security": {
            "GuardDuty": {"Enabled": True, "DetectorIds": ["d1"]},
            "SecurityHub": {"Enabled": True},
            "GuardDutyFindings": [], "SecurityHubFindings": [],
            "SecurityHubStandardsSummary": [], "AccessAnalyzerFindings": [],
            "ConfigRuleCompliance": [], "ConfigRecorder": {"Recording": True},
        },
        "Backup": {"BackupPlans": [], "PlansWithCrossRegionCopy": [], "FailedJobsRecent": []},
        "Observability": {"Alarms": [], "AlarmsWithNoActions": [], "AlarmsInAlarmState": [], "Dashboards": []},
        "Quotas": [],
    }


SCRIPTS = [
    pytest.param(
        discover,
        {
            "AccountId": "123456789012",
            "Regions": {"us-east-1": _empty_region_evidence()},
            "Global": {"DataStores": {"S3Buckets": [], "PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []}},
        },
        [],
        "architecture-discovery",
        id="discover",
    ),
    pytest.param(
        analyze_cost,
        {
            "CostReport": {
                "CostByService": [], "ReservationUtilization": {}, "SavingsPlansUtilization": {},
                "RightsizingRecommendations": [], "TrustedAdvisorCostChecks": [], "Anomalies": [], "Budgets": [],
            },
            "ComputeOptimizerEc2": {"us-east-1": []},
            "ComputeOptimizerEbs": {"us-east-1": []},
            "IdleResources": {"us-east-1": {"UnattachedVolumes": [], "UnassociatedEips": [], "StoppedInstances": []}},
        },
        [],
        "cost-optimization",
        id="analyze_cost",
    ),
    pytest.param(
        security_scan,
        {
            "Global": {
                "IamFindings": {
                    "ConsoleUsersWithoutMfa": [], "AccessKeysToReview": [],
                    "RootAccountRisks": [], "PasswordPolicySet": True,
                },
                "DataStores": {"PubliclyAccessibleBuckets": [], "UnencryptedBuckets": []},
                "CloudTrail": {
                    "Trails": [], "HasMultiRegionTrail": False,
                    "HasLoggingTrail": False, "HasLogFileValidation": False,
                },
            },
            "Regions": {
                "us-east-1": {
                    "Security": _empty_region_evidence()["Security"],
                    "WideOpenSecurityGroups": [],
                    "Compute": _empty_region_evidence()["Compute"],
                }
            },
        },
        [],
        "security-review",
        id="security_scan",
    ),
    pytest.param(
        traffic_analysis,
        {
            "Window": {"Start": "2024-01-01T00:00:00", "End": "2024-01-02T00:00:00"},
            "FlowLogAnalysis": {
                "top_talkers_by_bytes": [], "traffic_by_protocol": [], "rejected_traffic": [],
                "port_scan_candidates": [], "top_external_egress": [],
            },
            "NetworkFindings": [],
        },
        ["--log-group", "/vpc/flowlogs"],
        "network-traffic-analysis",
        id="traffic_analysis",
    ),
    pytest.param(
        collect_evidence,
        {
            "Regions": {"us-east-1": _empty_region_evidence()},
            "Global": {
                "Security": {
                    "IamFindings": {
                        "ConsoleUsersWithoutMfa": [], "AccessKeysToReview": [],
                        "RootAccountRisks": [], "PasswordPolicySet": True,
                    }
                },
                "DataStores": {},
                "Cost": {"Budgets": []},
                "CloudTrail": {"HasMultiRegionTrail": True, "HasLoggingTrail": True, "HasLogFileValidation": True},
            },
        },
        [],
        "well-architected-evidence",
        id="collect_evidence",
    ),
    pytest.param(
        analyze_organization,
        {"IsOrganizationsMember": False},
        [],
        "organizations-posture",
        id="analyze_organization",
    ),
    pytest.param(
        dr_readiness,
        {
            "Summary": {
                "Backup": {
                    "PlanCount": 0, "VaultCount": 0, "PlansWithCrossRegionCopy": 0,
                    "ProtectedResourceCount": 0, "RecentFailedJobs": 0,
                },
                "Rds": {"SingleAzInstances": [], "InstancesWithReadReplicas": [], "CrossRegionOrGlobalClusters": []},
                "S3": {"ReplicatedBuckets": [], "UnreplicatedBuckets": []},
                "Route53HealthChecks": [],
            },
            "Global": {"Route53HostedZones": []},
        },
        [],
        "dr-readiness",
        id="dr_readiness",
    ),
]


# ------------------------------------------------------------------ tests
@pytest.mark.parametrize("module,collect_return,extra_args,basename", SCRIPTS)
def test_main_writes_all_report_formats_and_exits_zero(
    module, collect_return, extra_args, basename, tmp_path, monkeypatch
):
    """Full pipeline: argparse -> collect -> build_report -> save.
    Only collect() is stubbed; the PDF really renders and files really land
    on disk under the requested --output-dir."""
    monkeypatch.setattr(module, "collect", lambda *a, **k: collect_return)

    exit_code = module.main(
        ["--region", "us-east-1", "--output-dir", str(tmp_path), "--formats", "md,html,pdf", *extra_args]
    )

    assert exit_code == 0
    for ext in ("md", "html", "pdf"):
        path = tmp_path / f"{basename}.{ext}"
        assert path.exists(), f"{module.__name__} did not write {path.name}"
        assert path.stat().st_size > 0
    assert (tmp_path / f"{basename}.pdf").read_bytes()[:4] == b"%PDF"


@pytest.mark.parametrize("module,collect_return,extra_args,basename", SCRIPTS)
def test_main_honors_formats_subset(module, collect_return, extra_args, basename, tmp_path, monkeypatch):
    """--formats md must write ONLY the Markdown file -- a regression here
    would silently spend PDF-rendering time the user opted out of."""
    monkeypatch.setattr(module, "collect", lambda *a, **k: collect_return)

    exit_code = module.main(
        ["--region", "us-east-1", "--output-dir", str(tmp_path), "--formats", "md", *extra_args]
    )

    assert exit_code == 0
    assert (tmp_path / f"{basename}.md").exists()
    assert not (tmp_path / f"{basename}.html").exists()
    assert not (tmp_path / f"{basename}.pdf").exists()


@pytest.mark.parametrize("module,collect_return,extra_args,basename", SCRIPTS)
def test_main_json_out_writes_parseable_evidence(
    module, collect_return, extra_args, basename, tmp_path, monkeypatch
):
    """--json-out must write the raw evidence as valid JSON -- downstream
    skills (aws-architecture-gap-analysis) read this file rather than
    re-querying AWS, so a malformed dump breaks them silently."""
    monkeypatch.setattr(module, "collect", lambda *a, **k: collect_return)
    json_path = tmp_path / "evidence.json"

    exit_code = module.main(
        [
            "--region", "us-east-1",
            "--output-dir", str(tmp_path),
            "--formats", "md",
            "--json-out", str(json_path),
            *extra_args,
        ]
    )

    assert exit_code == 0
    assert json_path.exists()
    with open(json_path) as fh:
        loaded = json.load(fh)
    assert isinstance(loaded, dict)
    assert loaded  # non-empty


@pytest.mark.parametrize("module,collect_return,extra_args,basename", SCRIPTS)
def test_main_creates_output_dir_if_missing(
    module, collect_return, extra_args, basename, tmp_path, monkeypatch
):
    """A user pointing --output-dir at a path that doesn't exist yet is the
    normal first-run case, not an error."""
    monkeypatch.setattr(module, "collect", lambda *a, **k: collect_return)
    nested = tmp_path / "does" / "not" / "exist"

    exit_code = module.main(
        ["--region", "us-east-1", "--output-dir", str(nested), "--formats", "md", *extra_args]
    )

    assert exit_code == 0
    assert (nested / f"{basename}.md").exists()


def test_traffic_analysis_requires_log_group_argument():
    """--log-group is the one genuinely required flag across all scripts;
    argparse must reject its absence rather than failing later at runtime."""
    with pytest.raises(SystemExit) as exc:
        traffic_analysis.parse_args(["--region", "us-east-1"])
    assert exc.value.code != 0


def test_collect_evidence_rejects_unknown_pillar():
    """--pillar is a choices= enum; a typo must fail fast at parse time."""
    with pytest.raises(SystemExit) as exc:
        collect_evidence.parse_args(["--pillar", "not-a-real-pillar"])
    assert exc.value.code != 0


def test_collect_evidence_accepts_every_documented_pillar():
    for pillar in (*collect_evidence.PILLARS, "all"):
        args = collect_evidence.parse_args(["--pillar", pillar])
        assert args.pillar == pillar


@pytest.mark.parametrize("module,collect_return,extra_args,basename", SCRIPTS)
def test_main_reports_written_paths_on_stdout(
    module, collect_return, extra_args, basename, tmp_path, monkeypatch, capsys
):
    """Claude reads these printed paths to know where the report landed."""
    monkeypatch.setattr(module, "collect", lambda *a, **k: collect_return)

    module.main(["--region", "us-east-1", "--output-dir", str(tmp_path), "--formats", "md", *extra_args])

    out = capsys.readouterr().out
    assert basename in out
    assert str(tmp_path) in out
