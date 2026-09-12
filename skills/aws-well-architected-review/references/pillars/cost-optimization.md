# Cost Optimization Pillar

Design principles: implement cloud financial management, adopt a consumption
model, measure overall efficiency, stop spending on undifferentiated heavy
lifting, analyze and attribute expenditure.

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| COST01 | How do you implement cloud financial management? | Cost Anomaly Detection configured (`Anomalies` non-empty implies a monitor exists), AWS Budgets actually configured | `Anomalies`, `Global.Cost.Budgets`; ask about a FinOps/CCoE practice if absent |
| COST02 | How do you govern usage? | Tagging coverage across resources; Service Control Policy coverage per account (Organizations-level) | Sample `Tags` fields; for SCP coverage hand off to the `aws-organizations-posture` skill (this evidence pack is single-account scoped) |
| COST03 | How do you monitor usage and cost? | Cost Explorer trend by service, cost anomalies | `CostByService`, `Anomalies` -- see the trend and anomaly charts |
| COST04 | How do you decommission resources? | Unattached EBS volumes, unassociated EIPs, stopped instances, orphaned manual snapshots | `UnattachedVolumes`, `UnassociatedEips`, `StoppedInstances`, `RdsManualSnapshots` |
| COST05 | How do you evaluate cost when you select services? | Rightsizing recommendations, Compute Optimizer findings | `RightsizingRecommendations`, `ComputeOptimizerEc2` |
| COST06 | How do you meet cost targets when selecting resource type/size/number? | Compute Optimizer EC2/EBS recommendations vs. actual instance types in use | `ComputeOptimizerEc2`, `ComputeOptimizerEbs` |
| COST07 | How do you use pricing models to reduce cost? | RI/Savings Plans utilization + coverage, purchase recommendations | `ReservationUtilization`, `ReservationCoverage`, `SavingsPlansUtilization`, `SavingsPlansPurchaseRecommendation`, `ReservedInstancePurchaseRecommendation` |
| COST08 | How do you plan for data transfer charges? | Cost by usage type for data transfer (extend Cost Explorer group-by if a deep dive is requested) | Not collected by default; extend `cost_and_usage_by_service` with `GroupBy: USAGE_TYPE` |
| COST09 | How do you manage demand and supply resources? | ASG scaling policies (ties to Reliability REL07); Savings Plans commitment vs. baseline usage | `AutoScalingGroups`, `SavingsPlansCoverage` |
| COST10 | How do you evaluate new services? | Not API-observable; ask about the account's service-adoption process | Direct question |
| COST11 | How do you evaluate the cost of effort? | Not API-observable; organizational process question | Direct question |

## Strategy-building guidance

When asked to "build a cost optimization strategy," synthesize (don't just
list) across these signals:

1. **Quick wins (this month):** decommission unattached EBS/EIPs, terminate
   long-stopped instances, delete unreferenced manual snapshots older than
   a retention threshold the user confirms.
2. **Rightsizing (this quarter):** apply Compute Optimizer + CE rightsizing
   recommendations, prioritized by estimated monthly savings.
3. **Commitment strategy (ongoing):** compare current RI/SP coverage against
   steady-state usage from the cost trend chart; recommend a coverage target
   (commonly 70-80% of steady-state baseline, leaving burst capacity
   on-demand) and cite the purchase recommendation's payback period.
4. **Governance:** tagging/budget alerts/anomaly-detection gaps found along
   the way -- these compound savings over time even though they aren't a
   one-time fix.

Always express savings estimates as *ranges cited from the AWS data*, not
invented numbers -- if Cost Explorer didn't return a recommendation, say so
rather than guessing a dollar figure.
