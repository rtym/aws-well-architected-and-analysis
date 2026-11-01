import boto3
from moto import mock_aws

from shared.awslib.collectors import containers


@mock_aws
def test_collect_region_containers_lists_ecs_cluster_and_service(ctx):
    ecs = boto3.client("ecs", region_name="us-east-1")
    ecs.create_cluster(clusterName="demo")
    task_def_arn = ecs.register_task_definition(
        family="web", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}]
    )["taskDefinition"]["taskDefinitionArn"]
    ecs.create_service(cluster="demo", serviceName="svc", taskDefinition=task_def_arn, desiredCount=1)

    result = containers.collect_region_containers(ctx, "us-east-1")

    assert len(result["EcsClusters"]) == 1
    cluster = result["EcsClusters"][0]
    assert cluster["clusterName"] == "demo"
    assert any(s["serviceName"] == "svc" for s in cluster["_Services"])


@mock_aws
def test_describe_eks_returns_empty_list_when_no_clusters(ctx):
    result = containers.describe_eks(ctx, "us-east-1")
    assert result == []


@mock_aws
def test_describe_eks_includes_nodegroups_and_fargate_profiles(ctx):
    eks = boto3.client("eks", region_name="us-east-1")
    eks.create_cluster(
        name="k8s",
        roleArn="arn:aws:iam::123456789012:role/eks",
        resourcesVpcConfig={"subnetIds": []},
    )
    eks.create_nodegroup(
        clusterName="k8s",
        nodegroupName="workers",
        subnets=["subnet-1"],
        nodeRole="arn:aws:iam::123456789012:role/nodes",
    )

    clusters = containers.describe_eks(ctx, "us-east-1")

    assert len(clusters) == 1
    assert clusters[0]["name"] == "k8s"
    assert [ng["nodegroupName"] for ng in clusters[0]["_Nodegroups"]] == ["workers"]
    assert clusters[0]["_FargateProfiles"] == []


@mock_aws
def test_describe_ecs_returns_empty_list_when_no_clusters(ctx):
    assert containers.describe_ecs(ctx, "us-east-1") == []
