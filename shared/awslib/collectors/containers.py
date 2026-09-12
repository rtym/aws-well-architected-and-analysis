"""ECS and EKS inventory."""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


def describe_ecs(ctx: AwsContext, region: str) -> list[dict]:
    ecs = ctx.client("ecs", region=region)
    clusters_arns = list(paginate(ecs, "list_clusters", "clusterArns"))
    if not clusters_arns:
        return []
    clusters = ecs.describe_clusters(
        clusters=clusters_arns, include=["SETTINGS", "STATISTICS"]
    )["clusters"]
    for cluster in clusters:
        service_arns = list(
            paginate(ecs, "list_services", "serviceArns", cluster=cluster["clusterArn"])
        )
        services = []
        for i in range(0, len(service_arns), 10):
            batch = service_arns[i : i + 10]
            services.extend(
                ecs.describe_services(cluster=cluster["clusterArn"], services=batch)["services"]
            )
        cluster["_Services"] = services
        cluster["_TaskArns"] = list(
            paginate(ecs, "list_tasks", "taskArns", cluster=cluster["clusterArn"])
        )
        cluster["_ContainerInstanceArns"] = list(
            paginate(
                ecs, "list_container_instances", "containerInstanceArns", cluster=cluster["clusterArn"]
            )
        )
    return clusters


@ignore_access_denied(default=list)
def describe_eks(ctx: AwsContext, region: str) -> list[dict]:
    eks = ctx.client("eks", region=region)
    names = list(paginate(eks, "list_clusters", "clusters"))
    clusters = []
    for name in names:
        cluster = eks.describe_cluster(name=name)["cluster"]
        nodegroup_names = list(
            paginate(eks, "list_nodegroups", "nodegroups", clusterName=name)
        )
        cluster["_Nodegroups"] = [
            eks.describe_nodegroup(clusterName=name, nodegroupName=ng)["nodegroup"]
            for ng in nodegroup_names
        ]
        cluster["_FargateProfiles"] = list(
            paginate(eks, "list_fargate_profiles", "fargateProfileNames", clusterName=name)
        )
        clusters.append(cluster)
    return clusters


def collect_region_containers(ctx: AwsContext, region: str) -> dict:
    return {
        "Region": region,
        "EcsClusters": describe_ecs(ctx, region),
        "EksClusters": describe_eks(ctx, region),
    }
