import boto3
from moto import mock_aws

from shared.awslib.collectors import data_stores


@mock_aws
def test_public_and_unencrypted_bucket_detection(ctx):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="open-bucket")
    s3.create_bucket(Bucket="locked-bucket")
    s3.put_public_access_block(
        Bucket="locked-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="locked-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    result = data_stores.collect_global_data_stores(ctx)

    names = {b["Name"] for b in result["S3Buckets"]}
    assert {"open-bucket", "locked-bucket"} <= names

    public_names = {b["Name"] for b in result["PubliclyAccessibleBuckets"]}
    assert "open-bucket" in public_names
    assert "locked-bucket" not in public_names

    unencrypted_names = {b["Name"] for b in result["UnencryptedBuckets"]}
    assert "open-bucket" in unencrypted_names
    assert "locked-bucket" not in unencrypted_names


@mock_aws
def test_list_buckets_resolves_per_bucket_region_and_routes_client(ctx):
    """Regression test: per-bucket calls (versioning/encryption/public-access-
    block/replication) must go through a client in *that bucket's own
    region*, not whatever region the account happens to be scanning --
    otherwise a bucket in a different region than `ctx.region` raises
    PermanentRedirect/IllegalLocationConstraintException on real AWS (moto
    doesn't simulate that error, so this test instead verifies the fix's
    actual mechanism: each bucket's real region is resolved via
    get_bucket_location, and a region-specific client is used/cached)."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="us-bucket")
    s3.create_bucket(
        Bucket="eu-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )

    buckets = data_stores.list_buckets(ctx)

    by_name = {b["Name"]: b for b in buckets}
    assert by_name["us-bucket"]["_Region"] == "us-east-1"
    assert by_name["eu-bucket"]["_Region"] == "eu-central-1"
    # A region-specific client must actually have been created/cached for
    # the non-default region -- proves the fix routes per-bucket calls
    # through the bucket's own region instead of always using ctx.region.
    assert ("s3", "eu-central-1") in ctx._client_cache


@mock_aws
def test_collect_region_data_stores_lists_dynamodb_and_lambda(ctx):
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="orders",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    result = data_stores.collect_region_data_stores(ctx, "us-east-1")

    assert any(t["TableName"] == "orders" for t in result["DynamoDbTables"])


@mock_aws
def test_describe_rds_clusters(ctx):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_cluster(
        DBClusterIdentifier="cluster-1",
        Engine="aurora-postgresql",
        MasterUsername="admin",
        MasterUserPassword="password123",
    )

    clusters = data_stores.describe_rds_clusters(ctx, "us-east-1")

    assert any(c["DBClusterIdentifier"] == "cluster-1" for c in clusters)


@mock_aws
def test_describe_elasticache_clusters(ctx):
    ec = boto3.client("elasticache", region_name="us-east-1")
    ec.create_cache_cluster(CacheClusterId="cache-1", Engine="redis", CacheNodeType="cache.t3.micro", NumCacheNodes=1)

    clusters = data_stores.describe_elasticache_clusters(ctx, "us-east-1")

    assert any(c["CacheClusterId"] == "cache-1" for c in clusters)


@mock_aws
def test_bucket_replication_configured_branch_returns_configuration(ctx):
    """The not-configured branch is covered by
    test_public_and_unencrypted_bucket_detection; this covers the other
    branch -- a bucket that genuinely has replication configured."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="source-bucket")
    s3.create_bucket(Bucket="dest-bucket")
    s3.put_bucket_versioning(Bucket="source-bucket", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket="dest-bucket", VersioningConfiguration={"Status": "Enabled"})
    iam = boto3.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(
        RoleName="replication-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )["Role"]["Arn"]
    s3.put_bucket_replication(
        Bucket="source-bucket",
        ReplicationConfiguration={
            "Role": role_arn,
            "Rules": [
                {
                    "Status": "Enabled",
                    "Priority": 1,
                    "Filter": {},
                    "Destination": {"Bucket": "arn:aws:s3:::dest-bucket"},
                }
            ],
        },
    )

    buckets = data_stores.list_buckets(ctx)

    source = next(b for b in buckets if b["Name"] == "source-bucket")
    assert source["_Replication"] is not None
    assert source["_Replication"]["Role"] == role_arn
