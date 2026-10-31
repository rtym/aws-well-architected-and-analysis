# Performance Efficiency Pillar

Design principles: democratize advanced technologies, go global in minutes,
use serverless architectures, experiment more often, consider mechanical
sympathy (match technology choice to the workload's actual access patterns).

Question set verified against the AWS Well-Architected Framework
(2025-02-25 framework documentation -- see `SOURCES.md`). AWS restructured
this pillar from eight questions to five; the current PERF03 covers all
data management (the old separate storage and database questions
together), PERF04 is networking, and PERF05 is a process question.

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| PERF01 | How do you select appropriate cloud resources and architecture patterns for your workload? | Mix of EC2/ECS/EKS/Lambda in use -- a single-pattern account (all EC2, nothing serverless) is a signal worth raising | `Instances`, `EcsClusters`, `EksClusters`, `LambdaFunctions` |
| PERF02 | How do you select and use compute resources in your workload? | Instance types in use vs. Compute Optimizer recommendations, Graviton adoption (`InstanceType` prefix `t4g`/`m7g`/etc.) | `Instances[].InstanceType`, `ComputeOptimizerEc2` |
| PERF03 | How do you store, manage, and access data in your workload? | EBS volume types (`gp2` vs `gp3`), unattached volumes as a sign of storage sprawl; RDS engine choice, DynamoDB vs. relational for the access pattern, ElastiCache presence as a caching layer | `Volumes[].VolumeType`, `RdsInstances[].Engine`, `DynamoDbTables`, `ElastiCacheClusters` |
| PERF04 | How do you select and configure networking resources in your workload? | VPC endpoints (Gateway/Interface) vs. NAT Gateway egress for AWS-service traffic, placement groups (not yet collected) | `VpcEndpoints`, `NatGateways` |
| PERF05 | What process do you use to support more performance efficiency for your workload? | Not API-observable (performance testing in the pipeline, KPI review practice); CloudWatch alarms/dashboards are the only infrastructure signal of ongoing performance visibility | Direct question, plus `Observability.Alarms`/`Observability.Dashboards` as supporting evidence only -- never mark "Yes" from alarms alone |

## Signals worth calling out

- `gp2` EBS volumes that could move to `gp3` for the same or better
  performance at lower cost (this is also a Cost Optimization overlap --
  cite both pillars).
- No VPC Gateway Endpoint for S3/DynamoDB in a VPC that has EC2/ECS workloads
  talking to those services -- traffic is unnecessarily hairpinning through
  a NAT Gateway (cost *and* latency impact).
- Instance types still on previous-generation families where a newer
  (often Graviton/ARM) family would be a drop-in performance/cost win.
