# Architecture viewpoints and the resource taxonomy behind them

Discovery output covers four AWS resource "tiers." Each maps to a
different architecture-documentation viewpoint you may be asked to
produce.

However you draw a viewpoint, it obeys the four rules in
`skills/aws-lucid-diagrams/references/diagram-conventions.md`: labelled
edges, expanded abbreviations, one clause per label, and a legend. Each
viewpoint below says under "connectivity to label" what that means for its
resources.

## Network viewpoint

**Resources:** `Vpcs`, `Subnets`, `RouteTables`, `InternetGateways`,
`NatGateways`, `VpcEndpoints`, `VpcPeeringConnections`,
`TransitGatewayAttachments`, `SecurityGroups`, `NetworkAcls`.

**What a good diagram shows:** VPC boundary, public vs. private subnet
split (infer from whether a subnet's route table has a `0.0.0.0/0` route
to an IGW vs. a NAT gateway), AZ spread, and cross-VPC/cross-account
connectivity (peering, Transit Gateway).

**Connectivity to label:** subnet -> Internet Gateway and subnet -> NAT
Gateway edges carry the destination range, the route table that provides it
and the direction (`0.0.0.0/0 via rtb-0a1: outbound only, replies allowed`);
peering and Transit Gateway edges carry the connection/attachment id and
whether routing is transitive; VPC endpoint edges carry `HTTPS 443` and the
fact that the traffic never leaves AWS.

**What to call out:** subnets with no route to anywhere (isolated),
security groups reachable from `0.0.0.0/0`, single-AZ NAT Gateway serving
multiple AZs' private subnets.

## Compute & container viewpoint

**Resources:** `Instances`, `AutoScalingGroups`, `LoadBalancersV2`,
`ClassicLoadBalancers`, `EcsClusters` (with `_Services`, `_TaskArns`,
`_ContainerInstanceArns`), `EksClusters` (with `_Nodegroups`,
`_FargateProfiles`).

**What a good diagram shows:** load balancer -> target group -> compute
(EC2/ECS service/EKS pod) fan-out; which subnets each compute resource
lives in (ties back to the network viewpoint).

**Connectivity to label:** listener protocol and port on the load balancer
edge, target port on the target edge (`HTTPS 443 to target group, HTTP 8080
to targets`); health-check path if the diagram is about availability; the
subnet each compute resource sits in.

**What to call out:** ECS services with `desiredCount` 0 or 1 (no
redundancy), EKS clusters with node groups but no Fargate profile (or vice
versa, depending on the workload's actual needs), load balancers with no
registered healthy targets.

## Data viewpoint

**Resources:** `RdsInstances`, `RdsClusters`, `DynamoDbTables`,
`ElastiCacheClusters`, `S3Buckets`, `LambdaFunctions` (as an
event-driven/data-processing signal).

**What a good diagram shows:** which compute tier talks to which data
store, read replica topology, cache-aside patterns (ElastiCache in front of
RDS/DynamoDB).

**Connectivity to label:** the database wire protocol and port
(`PostgreSQL, TCP 5432`, `Redis, TCP 6379`, `DynamoDB over HTTPS 443`),
whether the connection is encrypted in transit if the inventory says, and
the direction (read replica edges are one-way).

**What to call out:** RDS instances with `MultiAZ: false`, S3 buckets with
no encryption or public access block, DynamoDB tables on `PROVISIONED`
billing with no auto-scaling configured (check `_GlobalSecondaryIndexes`
and consider extending the collector if this needs to go deeper).

## Global viewpoint

**Resources:** `S3Buckets`, IAM (covered by the security-review skill, not
this one -- don't duplicate that analysis here).

Only S3 is genuinely global; everything else in this skill's inventory is
per-region and appears once per region scanned.
