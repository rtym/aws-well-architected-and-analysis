# Turning Cost Explorer output into a strategy, not a data dump

## The four tiers

**1. Quick wins (this month, near-zero risk)**

Sourced from `IdleResources` in the collected evidence: unattached EBS
volumes, unassociated Elastic IPs, long-stopped EC2 instances still
accruing EBS charges. These have no availability impact to remove/
terminate (confirm with the user before deleting anything -- a stopped
instance might be intentionally parked) and no design tradeoff. List them
by region with the exact resource IDs from the report.

**2. Rightsizing (this quarter, low-medium risk)**

Sourced from `RightsizingRecommendations` (Cost Explorer) and
`ComputeOptimizerEc2`/`ComputeOptimizerEbs`. Prioritize by estimated
savings where the tool provides it; note that rightsizing changes require
a maintenance window for anything not behind an Auto Scaling group with
instance refresh. Cross-check against the Well-Architected Performance
Efficiency pillar evidence (a "rightsizing" recommendation that would also
regress a documented performance requirement needs a caveat, not a blind
recommendation).

**3. Commitment strategy (ongoing decision, ties up capital/commitment)**

Sourced from `ReservationUtilization`, `ReservationCoverage`,
`SavingsPlansUtilization`, `SavingsPlansCoverage`, and the purchase
recommendation endpoints. The judgment call:

- Compare current coverage % against the monthly cost trend's steady-state
  floor (the lowest recurring monthly spend across the lookback window,
  visible in the trend chart) -- that floor is the safest base to cover
  with a 1-3 year commitment; spend above it should stay on-demand or a
  shorter-term commitment to preserve flexibility.
- A common starting target is 70-80% coverage of the steady-state
  baseline, leaving headroom for burst/seasonal variation -- treat this as
  a reasonable default to suggest, not a rule, and adjust based on how
  volatile the account's actual usage looks in the trend chart.
- Cite the purchase recommendation's own estimated monthly savings and
  payback/breakeven figures directly from the AWS response rather than
  computing your own estimate.

**4. Governance (compounds over time, no immediate dollar figure)**

Tagging coverage, whether Cost Anomaly Detection is configured
(`Anomalies` came back empty could mean "no anomalies" or "no monitor
configured" -- state which), Trusted Advisor cost-check coverage (requires
Business/Enterprise support). These don't have a one-time savings number
but prevent the same waste from re-accumulating after the quick wins are
cleaned up.

## What not to do

- Don't invent a dollar savings figure Cost Explorer/Compute Optimizer
  didn't return. If a section came back empty, say what that likely means
  (no RIs/SPs purchased yet, insufficient permissions, or genuinely no
  opportunity) rather than filling the gap with an estimate.
- Don't recommend a rightsizing or commitment change that contradicts a
  documented performance or reliability requirement without flagging the
  tension explicitly.
- Don't treat "idle" as "safe to delete" without the user confirming --
  parked/stopped resources are sometimes intentional (DR standby, seasonal
  workload).
