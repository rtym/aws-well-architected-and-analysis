"""Disaster-recovery readiness checks."""
import pytest

from shared.analysis import checks as engine
from shared.analysis import dr_checks


def dr_bundle(**summary_overrides) -> dict:
    """Evidence in which every DR check passes: a plan with cross-region
    copy, protected resources, Multi-AZ databases, and a health check."""
    summary = {
        "Backup": {"PlanCount": 1, "VaultCount": 1, "PlansWithCrossRegionCopy": 1, "ProtectedResourceCount": 4, "RecentFailedJobs": 0},
        "Rds": {"SingleAzInstances": [], "SingleAzClusters": [], "InstancesWithReadReplicas": [], "CrossRegionOrGlobalClusters": []},
        "S3": {"ReplicatedBuckets": [], "UnreplicatedBuckets": []},
        "Route53HealthChecks": [{"Id": "hc-1"}],
    }
    summary.update(summary_overrides)
    return {
        "Regions": {"us-east-1": {"DataStores": {"RdsInstances": [{"DBInstanceIdentifier": "db"}], "RdsClusters": [{"DBClusterIdentifier": "c"}]}}},
        "Global": {"Route53HostedZones": [{"Id": "Z1"}]},
        "Summary": summary,
    }


def _status(data) -> dict:
    return {r.check.id: r.status for r in dr_checks.evaluate_checks(data)}


def test_a_well_prepared_account_passes_every_check():
    assert set(_status(dr_bundle()).values()) == {engine.PASS}


def test_no_evidence_is_no_data():
    assert set(_status({}).values()) == {engine.NO_DATA}


@pytest.mark.parametrize(
    "check_id, overrides",
    [
        ("dr-backup-plan", {"Backup": {"PlanCount": 0, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 4, "RecentFailedJobs": 0}}),
        ("dr-backup-protected", {"Backup": {"PlanCount": 1, "PlansWithCrossRegionCopy": 1, "ProtectedResourceCount": 0, "RecentFailedJobs": 0}}),
        ("dr-cross-region-copy", {"Backup": {"PlanCount": 2, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 4, "RecentFailedJobs": 0}}),
        ("dr-backup-jobs", {"Backup": {"PlanCount": 1, "PlansWithCrossRegionCopy": 1, "ProtectedResourceCount": 4, "RecentFailedJobs": 3}}),
        ("dr-rds-multi-az", {"Rds": {"SingleAzInstances": [{"DBInstanceIdentifier": "db", "Engine": "mysql"}], "SingleAzClusters": []}}),
        ("dr-rds-cluster-az", {"Rds": {"SingleAzInstances": [], "SingleAzClusters": [{"DBClusterIdentifier": "c", "Engine": "aurora"}]}}),
        ("dr-health-checks", {"Route53HealthChecks": []}),
    ],
)
def test_each_check_fails_on_its_own_evidence(check_id, overrides):
    statuses = _status(dr_bundle(**overrides))
    assert statuses[check_id] == engine.FAIL
    assert [c for c, s in statuses.items() if s == engine.FAIL] == [check_id]


def test_cross_region_copy_is_not_judged_without_a_plan():
    data = dr_bundle(Backup={"PlanCount": 0, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 0, "RecentFailedJobs": 0})
    assert _status(data)["dr-cross-region-copy"] == engine.NO_DATA


def test_database_checks_need_databases_and_dns_checks_need_a_zone():
    data = dr_bundle(Route53HealthChecks=[])
    data["Regions"]["us-east-1"]["DataStores"] = {"RdsInstances": [], "RdsClusters": []}
    data["Global"]["Route53HostedZones"] = []
    statuses = _status(data)
    assert statuses["dr-rds-multi-az"] == statuses["dr-rds-cluster-az"] == statuses["dr-health-checks"] == engine.NO_DATA


def test_failed_job_count_lands_in_the_detail():
    data = dr_bundle(Backup={"PlanCount": 1, "PlansWithCrossRegionCopy": 1, "ProtectedResourceCount": 1, "RecentFailedJobs": 2})
    result = next(r for r in dr_checks.evaluate_checks(data) if r.check.id == "dr-backup-jobs")
    assert result.affected[0].detail == "2 failed job(s)"


def test_every_check_names_the_reliability_question_it_informs():
    for check, _ in dr_checks.CATALOG:
        assert check.question.startswith("REL") and check.finding and check.domain in dr_checks.DOMAINS
