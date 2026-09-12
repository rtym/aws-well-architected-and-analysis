# Sustainability Pillar

Design principles: understand your impact, establish sustainability goals,
maximize utilization, anticipate and adopt new, more efficient hardware and
software offerings, use managed services, reduce the downstream impact of
your cloud workloads.

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| SUS01 | How do you select Regions to support your sustainability goals? | Region(s) in scope for this review vs. AWS's published renewable-energy region list (changes over time -- ask the user to check the current list rather than hardcoding it here) | Region list from `--regions`/`--all-regions` |
| SUS02 | How do you take advantage of user behavior patterns? | Auto Scaling (scale-to-zero outside business hours), stopped-but-not-terminated instances as a signal of manual/inconsistent scheduling | `AutoScalingGroups`, `StoppedInstances` |
| SUS03 | How do you take advantage of software and architecture patterns? | Serverless/managed-service adoption (Lambda, DynamoDB on-demand) vs. always-on EC2 for spiky workloads | `LambdaFunctions`, `DynamoDbTables`, `Instances` |
| SUS04 | How do you take advantage of data access and usage patterns? | S3 storage class usage (not yet collected -- extend if a deep dive is requested), DynamoDB TTL configuration | Extend `data_stores` collector for `GetBucketLifecycleConfiguration` if needed |
| SUS05 | How do you select and use cloud hardware and services? | Graviton/ARM adoption (`InstanceType` prefixes `t4g`, `m6g`, `m7g`, `c7g`, etc.), `gp3` vs `gp2` EBS | `Instances[].InstanceType`, `Volumes[].VolumeType` |
| SUS06 | How do you take advantage of development and deployment processes? | Not directly API-observable; ask whether non-production environments are scheduled down outside working hours | Direct question |

## Overlap with Cost Optimization

Sustainability and Cost Optimization findings usually point at the same
underlying waste (idle EBS, stopped instances, oversized instances). When
producing a combined report, it's fine to cite the same evidence under both
pillars -- the framing differs (dollars vs. resource utilization/carbon
footprint) even when the fix is identical.
