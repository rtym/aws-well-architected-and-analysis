"""Disaster-recovery-readiness signals: Route 53 health checks (used for
DNS failover), plus the cross-service synthesis that answers REL13 --
backup coverage, RDS Multi-AZ/read-replica topology, and S3 cross-region
replication, pulled from the collectors that already gather them so this
module only adds what's genuinely new (Route 53) and composes the rest.
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


@ignore_access_denied(default=list)
def list_health_checks(ctx: AwsContext) -> list[dict]:
    """Route 53 is a global service; call once, not per-region.

    GetHealthCheckStatus rejects calculated health checks (their status is
    only visible in the console or CloudWatch). Calling it on one raised
    and aborted the whole DR collection -- and calculated checks are the
    usual building block of a DNS failover setup. They get `_Status: None`.
    """
    r53 = ctx.client("route53")
    checks = list(paginate(r53, "list_health_checks", "HealthChecks"))
    for check in checks:
        if check.get("HealthCheckConfig", {}).get("Type") == "CALCULATED":
            check["_Status"] = None
            continue
        status = r53.get_health_check_status(HealthCheckId=check["Id"])
        check["_Status"] = status.get("HealthCheckObservations", [])
    return checks


@ignore_access_denied(default=list)
def list_hosted_zones(ctx: AwsContext) -> list[dict]:
    r53 = ctx.client("route53")
    return list(paginate(r53, "list_hosted_zones", "HostedZones"))


def rds_dr_signals(rds_instances: list[dict], rds_clusters: list[dict]) -> dict:
    """Multi-AZ posture for standalone instances and for clusters.

    An instance that belongs to a cluster (Aurora, or a Multi-AZ DB
    cluster) always reports MultiAZ false at the instance level -- its
    availability comes from the cluster's spread of instances across AZs.
    Judging those per instance flagged every healthy Aurora member as
    single-AZ, so they're judged at the cluster level instead.
    """
    standalone = [i for i in rds_instances if not i.get("DBClusterIdentifier")]
    single_az = [i for i in standalone if not i.get("MultiAZ")]
    single_az_clusters = [c for c in rds_clusters if not c.get("MultiAZ")]
    with_read_replicas = [i for i in rds_instances if i.get("ReadReplicaDBInstanceIdentifiers")]
    cross_region_clusters = [
        c
        for c in rds_clusters
        if c.get("GlobalClusterIdentifier") or c.get("ReplicationSourceIdentifier")
    ]
    return {
        "SingleAzInstances": single_az,
        "SingleAzClusters": single_az_clusters,
        "InstancesWithReadReplicas": with_read_replicas,
        "CrossRegionOrGlobalClusters": cross_region_clusters,
    }


def s3_replication_signals(buckets: list[dict]) -> dict:
    replicated = [b for b in buckets if b.get("_Replication")]
    unreplicated = [b for b in buckets if not b.get("_Replication")]
    return {"ReplicatedBuckets": replicated, "UnreplicatedBuckets": unreplicated}


def dr_readiness_summary(
    backup_data: dict,
    rds_instances: list[dict],
    rds_clusters: list[dict],
    buckets: list[dict],
    health_checks: list[dict],
) -> dict:
    """One combined view for the DR-readiness report -- deliberately just
    assembles already-collected evidence rather than re-querying AWS."""
    return {
        "Backup": {
            "PlanCount": len(backup_data.get("BackupPlans", [])),
            "VaultCount": len(backup_data.get("BackupVaults", [])),
            "PlansWithCrossRegionCopy": len(backup_data.get("PlansWithCrossRegionCopy", [])),
            "RecentFailedJobs": len(backup_data.get("FailedJobsRecent", [])),
            "ProtectedResourceCount": len(backup_data.get("ProtectedResources", [])),
        },
        "Rds": rds_dr_signals(rds_instances, rds_clusters),
        "S3": s3_replication_signals(buckets),
        "Route53HealthChecks": health_checks,
    }
