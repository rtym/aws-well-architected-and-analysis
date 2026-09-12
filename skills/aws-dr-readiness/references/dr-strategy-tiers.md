# AWS disaster recovery strategy tiers

Source: AWS's "Disaster Recovery of Workloads on AWS" whitepaper,
`docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-options-in-the-cloud.html`.
The numeric RTO/RPO ranges below are the commonly-cited approximate AWS
figures for each tier, not exact guarantees for any specific workload --
always validate against a workload's actual documented RTO/RPO target
rather than treating these as thresholds.

Cost and complexity increase, and RTO/RPO shrink, monotonically down this
list.

## 1. Backup and Restore

No standing DR infrastructure -- periodic backups, restored on failover.

- **RTO:** hours. **RPO:** hours (set by backup frequency).
- **What implements it:** AWS Backup with cross-Region copy; RDS/Aurora/
  DynamoDB/EFS/EBS/Redshift/Neptune/DocumentDB/FSx snapshots; S3 Cross-
  Region Replication + versioning; IaC (CloudFormation/CDK) to redeploy
  compute from scratch; AMI backup/copy.
- **This skill's evidence for it:** `BackupPlans`/`BackupVaults` existing
  at all, `RdsManualSnapshots`, S3 bucket count vs. `ReplicatedBuckets`.
- **A legitimate end state**, not just a stepping stone -- fine for
  workloads whose stated RPO/RTO tolerance is "hours," which is common for
  internal tooling, batch/analytics workloads, and non-customer-facing
  systems.

## 2. Pilot Light

Core data stores always-on and continuously replicated; the compute/app
layer exists but is switched off, started only at failover.

- **RTO:** tens of minutes. **RPO:** minutes (near-zero with continuous
  replication).
- **What implements it:** everything in tier 1, plus RDS read replicas,
  Aurora Global Database, DynamoDB/DocumentDB global tables, ElastiCache
  Global Datastore, S3 Replication Time Control, pre-built golden AMIs,
  Route 53/Global Accelerator/CloudFront for failover routing. AWS Elastic
  Disaster Recovery (block-level replication) is effectively a managed
  implementation of this tier.
- **This skill's evidence for it:** `InstancesWithReadReplicas`,
  `CrossRegionOrGlobalClusters`, Route 53 health checks present.

## 3. Warm Standby

A scaled-down but fully running, traffic-capable duplicate environment in
the DR Region -- failover is a scale-up, not a cold start.

- **RTO:** minutes. **RPO:** seconds to minutes.
- **What implements it:** everything in tier 2, plus Auto Scaling to scale
  DR-Region capacity up on failover. Provisioning full capacity upfront
  instead of scaling on failover is a variant sometimes called **Hot
  Standby** -- faster RTO, higher steady-state cost.
- **This skill's evidence for it:** Auto Scaling groups present in a
  secondary region with a non-trivial minimum size (compare against
  `aws-architecture-discovery`'s inventory for the DR region, since this
  skill alone doesn't cross-reference ASG configuration).

## 4. Multi-site Active/Active

The full workload runs simultaneously in two or more Regions, all serving
live production traffic -- there is no failover *event* for an
infrastructure-level Region loss.

- **RTO:** near-zero for infrastructure failure (traffic simply routes
  around the lost Region). **RPO:** still non-zero for data-corruption or
  application-level failures, since those replicate to every active site
  just as fast as legitimate writes do -- active-active protects against
  infrastructure loss, not against bad data.
- **What implements it:** everything above, plus Route 53/Global
  Accelerator weighted/geoproximity/latency-based routing, Aurora Global
  Database write-forwarding, DynamoDB Global Tables (last-writer-wins
  conflict resolution), S3 bidirectional replication with write-
  partitioning by key to avoid collisions.
- **Highest cost and complexity tier** -- only recommend it when the
  stated business requirement genuinely calls for near-zero RTO on
  infrastructure loss; it is not a default target.

## How to use this in a report

For each workload (or the account as a whole, if the user can't break it
down by workload), state which tier the *current* evidence matches, then
ask what tier the business actually needs before recommending a change --
recommending Multi-site Active/Active for a workload whose real
requirement is "restore within a business day" is over-engineering, not a
better answer.
