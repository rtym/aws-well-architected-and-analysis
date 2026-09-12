import boto3
from moto import mock_aws

from shared.awslib.collectors import backup, dr


@mock_aws
def test_backup_plans_with_cross_region_copy(ctx):
    bk = boto3.client("backup", region_name="us-east-1")
    iam = boto3.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(
        RoleName="backup-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )["Role"]["Arn"]
    vault = bk.create_backup_vault(BackupVaultName="primary-vault")
    bk.create_backup_plan(
        BackupPlan={
            "BackupPlanName": "daily",
            "Rules": [
                {
                    "RuleName": "daily-rule",
                    "TargetBackupVaultName": "primary-vault",
                    "ScheduleExpression": "cron(0 5 * * ? *)",
                    "CopyActions": [
                        {"DestinationBackupVaultArn": "arn:aws:backup:eu-west-1:123456789012:backup-vault:dr-vault"}
                    ],
                }
            ],
        }
    )

    plans = backup.list_backup_plans(ctx, "us-east-1")
    assert len(plans) == 1
    cross_region = backup.plans_with_cross_region_copy(plans)
    assert len(cross_region) == 1

    vaults = backup.list_backup_vaults(ctx, "us-east-1")
    assert any(v["BackupVaultName"] == "primary-vault" for v in vaults)
    _ = role_arn, vault


@mock_aws
def test_backup_plans_without_copy_action_not_flagged(ctx):
    bk = boto3.client("backup", region_name="us-east-1")
    bk.create_backup_vault(BackupVaultName="primary-vault")
    bk.create_backup_plan(
        BackupPlan={
            "BackupPlanName": "daily",
            "Rules": [{"RuleName": "r", "TargetBackupVaultName": "primary-vault", "ScheduleExpression": "cron(0 5 * * ? *)"}],
        }
    )

    plans = backup.list_backup_plans(ctx, "us-east-1")
    assert backup.plans_with_cross_region_copy(plans) == []


def test_rds_dr_signals_flags_single_az_and_replicas():
    instances = [
        {"DBInstanceIdentifier": "db-1", "MultiAZ": False},
        {"DBInstanceIdentifier": "db-2", "MultiAZ": True, "ReadReplicaDBInstanceIdentifiers": ["db-2-replica"]},
    ]
    clusters = [{"DBClusterIdentifier": "cluster-1", "GlobalClusterIdentifier": "global-1"}]

    signals = dr.rds_dr_signals(instances, clusters)

    assert [i["DBInstanceIdentifier"] for i in signals["SingleAzInstances"]] == ["db-1"]
    assert [i["DBInstanceIdentifier"] for i in signals["InstancesWithReadReplicas"]] == ["db-2"]
    assert len(signals["CrossRegionOrGlobalClusters"]) == 1


def test_s3_replication_signals_splits_replicated_and_not():
    buckets = [{"Name": "a", "_Replication": {"Role": "x"}}, {"Name": "b", "_Replication": None}]
    signals = dr.s3_replication_signals(buckets)
    assert [b["Name"] for b in signals["ReplicatedBuckets"]] == ["a"]
    assert [b["Name"] for b in signals["UnreplicatedBuckets"]] == ["b"]


@mock_aws
def test_route53_health_checks_collected(ctx):
    r53 = boto3.client("route53", region_name="us-east-1")
    r53.create_health_check(
        CallerReference="ref-1",
        HealthCheckConfig={"Type": "HTTPS", "FullyQualifiedDomainName": "example.com", "Port": 443},
    )

    checks = dr.list_health_checks(ctx)
    assert len(checks) == 1


@mock_aws
def test_list_hosted_zones_collected(ctx):
    r53 = boto3.client("route53", region_name="us-east-1")
    r53.create_hosted_zone(Name="example.com", CallerReference="ref-1")

    zones = dr.list_hosted_zones(ctx)

    assert any(z["Name"] == "example.com." for z in zones)


def test_dr_readiness_summary_assembles_all_inputs():
    backup_data = {
        "BackupPlans": [{}],
        "BackupVaults": [{}],
        "PlansWithCrossRegionCopy": [{}],
        "FailedJobsRecent": [],
        "ProtectedResources": [{}, {}],
    }
    summary = dr.dr_readiness_summary(
        backup_data,
        rds_instances=[{"DBInstanceIdentifier": "db-1", "MultiAZ": False}],
        rds_clusters=[],
        buckets=[{"Name": "a", "_Replication": None}],
        health_checks=[{"Id": "hc-1"}],
    )
    assert summary["Backup"]["PlanCount"] == 1
    assert summary["Backup"]["ProtectedResourceCount"] == 2
    assert len(summary["Rds"]["SingleAzInstances"]) == 1
    assert summary["Route53HealthChecks"] == [{"Id": "hc-1"}]
