"""Disaster-recovery readiness checks, evaluated against the evidence
bundle `skills/aws-dr-readiness/scripts/dr_readiness.py` collects.

These measure what is configured, not whether it meets a recovery
objective: a passing check says the mechanism exists. No Security Hub
control covers most of them, so severities are plugin-assigned and the
Well-Architected question each one informs is recorded instead.
"""
from __future__ import annotations

from .checks import Affected, Check, CheckResult, evaluate

BACKUP = "Backup"
DATABASES = "Database resilience"
FAILOVER = "Failover"
DOMAINS = (BACKUP, DATABASES, FAILOVER)


def _summary(data: dict) -> dict:
    return data.get("Summary") or {}


def _backup(data: dict) -> dict | None:
    return _summary(data).get("Backup")


def rds_instance_count(data: dict) -> int:
    return sum(len((r.get("DataStores") or {}).get("RdsInstances") or []) for r in (data.get("Regions") or {}).values())


def rds_cluster_count(data: dict) -> int:
    return sum(len((r.get("DataStores") or {}).get("RdsClusters") or []) for r in (data.get("Regions") or {}).values())


def _plans(data):
    b = _backup(data)
    if b is None:
        return None
    return [] if b.get("PlanCount") else [Affected("account", "global", "no AWS Backup plan")]


def _protected(data):
    b = _backup(data)
    if b is None:
        return None
    return [] if b.get("ProtectedResourceCount") else [Affected("account", "global", "no resource has a recovery point")]


def _cross_region(data):
    b = _backup(data)
    if b is None or not b.get("PlanCount"):
        return None  # nothing to copy without a plan; the plan check covers it
    return [] if b.get("PlansWithCrossRegionCopy") else [Affected("account", "global", "no plan copies to another region")]


def _failed_jobs(data):
    b = _backup(data)
    if b is None:
        return None
    failed = b.get("RecentFailedJobs") or 0
    return [Affected("account", "global", f"{failed} failed job(s)")] if failed else []


def _single_az_instances(data):
    rds = _summary(data).get("Rds")
    if rds is None or not rds_instance_count(data):
        return None
    return [Affected(str(i.get("DBInstanceIdentifier")), "global", i.get("Engine") or "") for i in rds.get("SingleAzInstances") or []]


def _single_az_clusters(data):
    rds = _summary(data).get("Rds")
    if rds is None or "SingleAzClusters" not in rds or not rds_cluster_count(data):
        return None
    return [Affected(str(c.get("DBClusterIdentifier")), "global", c.get("Engine") or "") for c in rds["SingleAzClusters"]]


def _health_checks(data):
    zones = (data.get("Global") or {}).get("Route53HostedZones")
    checks = _summary(data).get("Route53HealthChecks")
    if not zones or checks is None:
        return None  # no hosted zone: DNS failover isn't the mechanism here
    return [] if checks else [Affected("account", "global", f"{len(zones)} hosted zone(s), no health check")]


CATALOG = [
    (Check("dr-backup-plan", "An AWS Backup plan exists", BACKUP, "HIGH",
           "Create an AWS Backup plan for the critical resources, with a schedule that meets the RPO",
           "Low", question="REL09", finding="No AWS Backup plan"), _plans),
    (Check("dr-backup-protected", "AWS Backup holds recovery points for at least one resource", BACKUP, "HIGH",
           "Assign resources to the backup plan (by tag or ARN) and confirm the first recovery points land",
           "Low", question="REL09", finding="AWS Backup protects no resources"), _protected),
    (Check("dr-cross-region-copy", "A backup plan copies recovery points to another region", BACKUP, "MEDIUM",
           "Add a cross-region copy rule to the plans that protect critical data",
           "Low", question="REL13", finding="No backup plan copies to another region"), _cross_region),
    (Check("dr-backup-jobs", "No backup job failed recently", BACKUP, "MEDIUM",
           "Investigate the failed backup jobs; a backup that never completes can't be restored",
           "Medium", question="REL09", finding="Recent backup jobs failed"), _failed_jobs),
    (Check("dr-rds-multi-az", "Standalone RDS instances run Multi-AZ", DATABASES, "MEDIUM",
           "Convert the listed instances to Multi-AZ (a modify operation with a brief failover)",
           "Medium", question="REL10", finding="Single-AZ RDS instances"), _single_az_instances),
    (Check("dr-rds-cluster-az", "DB clusters span more than one Availability Zone", DATABASES, "MEDIUM",
           "Add a reader instance in another Availability Zone to each listed cluster",
           "Medium", question="REL10", finding="DB clusters in a single Availability Zone"), _single_az_clusters),
    (Check("dr-health-checks", "Route 53 health checks exist for DNS failover", FAILOVER, "LOW",
           "Create health checks and failover records for the endpoints DNS should fail over, if DNS is the failover mechanism",
           "Medium", question="REL11", finding="Hosted zones without any health check"), _health_checks),
]


def evaluate_checks(data: dict) -> list[CheckResult]:
    return evaluate(CATALOG, data)
