"""Data-tier inventory: RDS, DynamoDB, S3, ElastiCache, Lambda, API Gateway."""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


def describe_rds_instances(ctx: AwsContext, region: str) -> list[dict]:
    rds = ctx.client("rds", region=region)
    return list(paginate(rds, "describe_db_instances", "DBInstances"))


def describe_rds_clusters(ctx: AwsContext, region: str) -> list[dict]:
    rds = ctx.client("rds", region=region)
    return list(paginate(rds, "describe_db_clusters", "DBClusters"))


def describe_rds_snapshots(ctx: AwsContext, region: str) -> list[dict]:
    rds = ctx.client("rds", region=region)
    return list(paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"))


def list_dynamodb_tables(ctx: AwsContext, region: str) -> list[dict]:
    ddb = ctx.client("dynamodb", region=region)
    names = list(paginate(ddb, "list_tables", "TableNames"))
    return [ddb.describe_table(TableName=n)["Table"] for n in names]


def list_buckets(ctx: AwsContext) -> list[dict]:
    """S3 is global; `list_buckets` itself is called once, not per-region.
    Every per-bucket call below, however, must go through a client in that
    *specific bucket's own region* -- calling e.g. get_bucket_versioning
    from a client pinned to a different region raises PermanentRedirect/
    IllegalLocationConstraintException, which is normal multi-region
    account state (most accounts have buckets in more than one region),
    not a real error to let propagate.
    """
    s3 = ctx.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        bucket_region = _bucket_region(s3, b["Name"])
        bucket_client = ctx.client("s3", region=bucket_region) if bucket_region else s3
        b["_Region"] = bucket_region
        b["_PublicAccessBlock"] = _bucket_public_access_block(bucket_client, b["Name"])
        b["_Encryption"] = _bucket_encryption(bucket_client, b["Name"])
        b["_Versioning"] = _bucket_versioning(bucket_client, b["Name"])
        b["_Replication"] = _bucket_replication(bucket_client, b["Name"])
    return buckets


@ignore_access_denied(default=lambda: None)
def _bucket_region(s3, name: str) -> str | None:
    """`LocationConstraint` is empty/None for us-east-1 (a long-standing S3
    API quirk) -- normalize that to the real region name."""
    constraint = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    return constraint or "us-east-1"


@ignore_access_denied(default=lambda: None)
def _bucket_versioning(s3, name: str):
    return s3.get_bucket_versioning(Bucket=name).get("Status")


@ignore_access_denied(default=lambda: None)
def _bucket_replication(s3, name: str):
    try:
        return s3.get_bucket_replication(Bucket=name)["ReplicationConfiguration"]
    except s3.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
            return None
        raise


@ignore_access_denied(default=lambda: None)
def _bucket_public_access_block(s3, name: str):
    try:
        return s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except s3.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


@ignore_access_denied(default=lambda: None)
def _bucket_encryption(s3, name: str):
    try:
        return s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]
    except s3.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return None
        raise


def describe_elasticache_clusters(ctx: AwsContext, region: str) -> list[dict]:
    ec = ctx.client("elasticache", region=region)
    return list(paginate(ec, "describe_cache_clusters", "CacheClusters"))


def list_lambda_functions(ctx: AwsContext, region: str) -> list[dict]:
    lam = ctx.client("lambda", region=region)
    return list(paginate(lam, "list_functions", "Functions"))


def publicly_accessible_buckets(buckets: list[dict]) -> list[dict]:
    findings = []
    for b in buckets:
        pab = b.get("_PublicAccessBlock") or {}
        blocked = all(
            pab.get(k, False)
            for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
        if not blocked:
            findings.append({"Name": b["Name"], "PublicAccessBlock": pab})
    return findings


def unencrypted_buckets(buckets: list[dict]) -> list[dict]:
    return [{"Name": b["Name"]} for b in buckets if not b.get("_Encryption")]


def collect_region_data_stores(ctx: AwsContext, region: str) -> dict:
    return {
        "Region": region,
        "RdsInstances": describe_rds_instances(ctx, region),
        "RdsClusters": describe_rds_clusters(ctx, region),
        "RdsManualSnapshots": describe_rds_snapshots(ctx, region),
        "DynamoDbTables": list_dynamodb_tables(ctx, region),
        "ElastiCacheClusters": describe_elasticache_clusters(ctx, region),
        "LambdaFunctions": list_lambda_functions(ctx, region),
    }


def collect_global_data_stores(ctx: AwsContext) -> dict:
    buckets = list_buckets(ctx)
    return {
        "S3Buckets": buckets,
        "PubliclyAccessibleBuckets": publicly_accessible_buckets(buckets),
        "UnencryptedBuckets": unencrypted_buckets(buckets),
    }
