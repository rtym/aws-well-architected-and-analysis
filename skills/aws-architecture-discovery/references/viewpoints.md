# Architecture viewpoints and the resource taxonomy behind them

Discovery output covers four AWS resource "tiers." Each maps to a
different architecture-documentation viewpoint you may be asked to
produce.

## Network viewpoint

**Resources:** `Vpcs`, `Subnets`, `RouteTables`, `InternetGateways`,
`NatGateways`, `VpcEndpoints`, `VpcPeeringConnections`,
`TransitGatewayAttachments`, `SecurityGroups`, `NetworkAcls`.

**What a good diagram shows:** VPC boundary, public vs. private subnet
split (infer from whether a subnet's route table has a `0.0.0.0/0` route
to an IGW vs. a NAT gateway), AZ spread, and cross-VPC/cross-account
connectivity (peering, Transit Gateway).

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

**What to call out:** RDS instances with `MultiAZ: false`, S3 buckets with
no encryption or public access block, DynamoDB tables on `PROVISIONED`
billing with no auto-scaling configured (check `_GlobalSecondaryIndexes`
and consider extending the collector if this needs to go deeper).

## Global viewpoint

**Resources:** `S3Buckets`, IAM (covered by the security-review skill, not
this one -- don't duplicate that analysis here).

Only S3 is genuinely global; everything else in this skill's inventory is
per-region and appears once per region scanned.
