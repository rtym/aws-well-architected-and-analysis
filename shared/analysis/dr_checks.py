"""Disaster-recovery readiness checks, evaluated against the evidence
bundle `skills/aws-dr-readiness/scripts/dr_readiness.py` collects.

These measure what is configured, not whether it meets a recovery
objective: a passing check says the mechanism exists. No Security Hub
control covers most of them, so severities are plugin-assigned and the
Well-Architected question each one informs is recorded instead.

A count of zero only fails a check when the scan could read what it was
counting. When the call behind it was denied (`AccessDenied` in the
evidence), the check is NO DATA: "no backup plan" and "not allowed to list
backup plans" are different findings.
"""
from __future__ import annotations

from . import access
from .checks import NO_DATA, Affected, Check, CheckResult, evaluate

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
    if b.get("PlanCount"):
        return []
    if access.was_denied(data, "list_backup_plans"):
        return None
    return [Affected("account", "global", "no AWS Backup plan")]


def _protected(data):
    b = _backup(data)
    if b is None:
        return None
    if b.get("ProtectedResourceCount"):
        return []
    if access.was_denied(data, "list_protected_resources"):
        return None
    return [Affected("account", "global", "no resource has a recovery point")]


def _cross_region(data):
    b = _backup(data)
    if b is None or not b.get("PlanCount"):
        return None  # nothing to copy without a plan; the plan check covers it
    if b.get("PlansWithCrossRegionCopy"):
        return []
    if access.was_denied(data, "list_backup_plans"):
        return None  # a plan in an unread region may be the one that copies
    return [Affected("account", "global", "no plan copies to another region")]


def _failed_jobs(data):
    b = _backup(data)
    if b is None:
        return None
    failed = b.get("RecentFailedJobs") or 0
    if failed:
        return [Affected("account", "global", f"{failed} failed job(s)")]
    return None if access.was_denied(data, "list_recent_jobs") else []


def _single_az_instances(data):
    rds = _summary(data).get("Rds")
    if rds is None or not rds_instance_count(data):
        return None
    affected = [Affected(str(i.get("DBInstanceIdentifier")), "global", i.get("Engine") or "") for i in rds.get("SingleAzInstances") or []]
    return affected or (None if access.was_denied(data, "describe_rds_instances") else [])


def _single_az_clusters(data):
    rds = _summary(data).get("Rds")
    if rds is None or "SingleAzClusters" not in rds or not rds_cluster_count(data):
        return None
    affected = [Affected(str(c.get("DBClusterIdentifier")), "global", c.get("Engine") or "") for c in rds["SingleAzClusters"]]
    return affected or (None if access.was_denied(data, "describe_rds_clusters") else [])


def _health_checks(data):
    zones = (data.get("Global") or {}).get("Route53HostedZones")
    checks = _summary(data).get("Route53HealthChecks")
    if not zones or checks is None:
        return None  # no hosted zone: DNS failover isn't the mechanism here
    if checks:
        return []
    if access.was_denied(data, "list_health_checks"):
        return None
    return [Affected("account", "global", f"{len(zones)} hosted zone(s), no health check")]


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


# The collectors each check's evidence comes from.
COLLECTORS = {
    "dr-backup-plan": ("list_backup_plans",),
    "dr-backup-protected": ("list_protected_resources",),
    "dr-cross-region-copy": ("list_backup_plans",),
    "dr-backup-jobs": ("list_recent_jobs",),
    "dr-rds-multi-az": ("describe_rds_instances",),
    "dr-rds-cluster-az": ("describe_rds_clusters",),
    "dr-health-checks": ("list_health_checks", "list_hosted_zones"),
}
DENIED_NOTE = "Not evaluated: the scan was denied access to evidence this check needs (see Access Gaps)."


def evaluate_checks(data: dict) -> list[CheckResult]:
    results = evaluate(CATALOG, data)
    for r in results:
        if r.status == NO_DATA and access.was_denied(data, *COLLECTORS[r.check.id]):
            r.note = DENIED_NOTE
    return results
