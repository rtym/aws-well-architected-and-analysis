# Reliability Pillar

Design principles: automatically recover from failure, test recovery
procedures, scale horizontally, stop guessing capacity, manage change
through automation.

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| REL01 | How do you manage service quotas and constraints? | Configured value for a curated set of commonly-hit quotas per region | `Quotas` (per-region evidence) -- compare against actual resource counts from the discovery inventory; `pending_quota_increase_requests()` is also available if a deeper check is requested |
| REL02 | How do you plan your network topology? | VPC/subnet spread across AZs, Transit Gateway attachments, VPC peering | `Vpcs`, `Subnets` (`AvailabilityZone` field), `TransitGatewayAttachments`, `VpcPeeringConnections` |
| REL03 | How do you design your workload service architecture? | ECS/EKS service counts and desired task counts, Lambda as decoupling signal | `EcsClusters[]._Services`, `EksClusters`, `LambdaFunctions` |
| REL04 | How do you prevent failures in a distributed system? | ALB/NLB health checks, target group health check config | `LoadBalancersV2[]._TargetGroups` |
| REL05 | How do you mitigate/withstand failures? | Auto Scaling group min/max/desired spread across AZs | `AutoScalingGroups` |
| REL06 | How do you monitor workload resources? | CloudWatch alarms and dashboards actually configured -- and whether alarms have any notification action attached | `Observability.Alarms`, `Observability.AlarmsWithNoActions`, `Observability.Dashboards` |
| REL07 | How do you adapt to changes in demand? | ASG scaling policies, DynamoDB on-demand vs provisioned billing mode | `AutoScalingGroups`, `DynamoDbTables[].BillingModeSummary` |
| REL08 | How do you implement change? | Not API-observable (CI/CD process); ask the user about deployment pipeline and change management | Direct question |
| REL09 | How do you back up data? | RDS automated backup retention, manual snapshots, EBS snapshots, and centralized AWS Backup plan/vault coverage | `RdsInstances[].BackupRetentionPeriod`, `RdsManualSnapshots`, `Snapshots`, `Backup.BackupPlans`/`BackupVaults` -- for a full DR-readiness deep-dive (cross-region copy, RTO/RPO framing) hand off to the `aws-dr-readiness` skill |
| REL10 | How do you use fault isolation to protect your workload? | Multi-AZ subnet layout, multi-region posture (if `--all-regions` was used) | `Subnets` grouped by AZ, region count in the inventory |
| REL11 | How do you design for component failures? | RDS `MultiAZ` flag, ASG across >=2 AZs, NAT gateway count vs. AZ count | `RdsInstances[].MultiAZ`, `NatGateways` vs `Subnets` AZ spread |
| REL12 | How do you test reliability? | Not API-observable (game days, chaos engineering); ask the user | Direct question |
| REL13 | How do you plan for disaster recovery? | Cross-region snapshots/replicas, AWS Backup cross-region copy | `RdsInstances[].ReadReplicaDBInstanceIdentifiers`, `Backup.PlansWithCrossRegionCopy` -- Route 53 health checks, S3 cross-region replication, and mapping the account's actual posture against AWS's DR strategy tiers (backup & restore / pilot light / warm standby / multi-site active-active) is the `aws-dr-readiness` skill's job, not this evidence pack's; hand off there for a full REL13 assessment |

## Common risk patterns to flag automatically

- A VPC with only one NAT Gateway across multiple AZs -- single point of failure for
  outbound connectivity from private subnets.
- An RDS instance with `MultiAZ: false` in a production-tagged environment.
- An Auto Scaling group with `MinSize == MaxSize == DesiredCapacity` (no
  actual elasticity, defeats the point of an ASG).
- Load balancer target groups with no health check configured or a health
  check pointing at a path that always 200s regardless of app health.
