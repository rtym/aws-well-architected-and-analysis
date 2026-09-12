# Performance Efficiency Pillar

Design principles: democratize advanced technologies, go global in minutes,
use serverless architectures, experiment more often, consider mechanical
sympathy (match technology choice to the workload's actual access patterns).

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| PERF01 | How do you select the best performing architecture? | Mix of EC2/ECS/EKS/Lambda in use -- a single-pattern account (all EC2, nothing serverless) is a signal worth raising | `Instances`, `EcsClusters`, `EksClusters`, `LambdaFunctions` |
| PERF02 | How do you select your compute solution? | Instance types in use vs. Compute Optimizer recommendations, Graviton adoption (`InstanceType` prefix `t4g`/`m7g`/etc.) | `Instances[].InstanceType`, `ComputeOptimizerEc2` |
| PERF03 | How do you select your storage solution? | EBS volume types (`gp2` vs `gp3`), unattached volumes as a sign of storage sprawl | `Volumes[].VolumeType` |
| PERF04 | How do you select your database solution? | RDS engine choice, DynamoDB vs. relational for the access pattern, ElastiCache presence as a caching layer | `RdsInstances[].Engine`, `DynamoDbTables`, `ElastiCacheClusters` |
| PERF05 | How do you configure your networking solution? | VPC endpoints (Gateway/Interface) vs. NAT Gateway egress for AWS-service traffic, placement groups (not yet collected) | `VpcEndpoints`, `NatGateways` |

## Signals worth calling out

- `gp2` EBS volumes that could move to `gp3` for the same or better
  performance at lower cost (this is also a Cost Optimization overlap --
  cite both pillars).
- No VPC Gateway Endpoint for S3/DynamoDB in a VPC that has EC2/ECS workloads
  talking to those services -- traffic is unnecessarily hairpinning through
  a NAT Gateway (cost *and* latency impact).
- Instance types still on previous-generation families where a newer
  (often Graviton/ARM) family would be a drop-in performance/cost win.
