---
name: aws-cost-optimization
description: >
  Analyze AWS cost and usage trends, Reserved Instance and Savings Plans
  coverage/utilization, rightsizing opportunities (Cost Explorer +
  Compute Optimizer), and idle-resource waste (unattached EBS,
  unassociated Elastic IPs, stopped instances) via boto3/Cost Explorer,
  then build a prioritized cost-optimization strategy and a
  Markdown/HTML/PDF report with trend, distribution, and waste charts.
  Use this skill when someone asks for "cost optimization", "cost
  analysis", "reduce our AWS bill", "reserved instance strategy",
  "savings plans review", "rightsizing", "find idle resources", "cost
  report", or "FinOps review".
---

# AWS Cost Optimization

Analyzes an account's Cost Explorer data, RI/Savings Plans posture, and
idle-resource waste, then helps build an actual prioritized savings
strategy -- not just a data dump. Read-only; Cost Explorer, Compute
Optimizer, and Trusted Advisor calls are all `Get*`/`Describe*`. See
`${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy (note: Trusted
Advisor cost checks require a Business/Enterprise support plan and are
silently omitted otherwise).

## Before you start

Load the strategy-building reference -- it has the framework for turning
raw Cost Explorer output into a prioritized plan instead of just listing
numbers:

```
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-cost-optimization/references/strategy-framework.md
```

Confirm with the user: profile/credentials, lookback window (default 90
days), and which region(s) to check for Compute Optimizer / idle-resource
findings (Cost Explorer itself is account-wide and always `us-east-1`
under the hood -- the script handles that automatically).

## Workflow

### Step 1 -- Run the collector

```bash
${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script ${CLAUDE_PLUGIN_ROOT}/skills/aws-cost-optimization/scripts/analyze_cost.py \
  --profile <profile> \
  --lookback-days 90 \
  --compute-optimizer-regions us-east-1,eu-west-1 \
  --json-out reports/output/cost-evidence.json \
  --output-dir reports/output \
  --formats md,html,pdf
```

`run-skill-script` runs the script in the plugin's own Python virtualenv. On
first use it creates that virtualenv and installs `requirements.txt` (about a
minute; progress goes to stderr). If it exits saying Python 3.11+ is missing,
relay its install hint to the user rather than retrying. If only PDF export
fails (WeasyPrint needs Pango: `brew install pango` on macOS), the Markdown
and HTML reports are already written -- rerun with `--formats md,html` or
tell the user how to enable PDF.

This produces a report with: monthly cost trend by top service, cost
distribution pie chart, RI/Savings Plans utilization, Cost Explorer
rightsizing recommendations, Compute Optimizer EC2 recommendations, idle
resource counts per region with a chart, Trusted Advisor cost checks (if
available), and cost anomalies (if Cost Anomaly Detection is configured).

### Step 2 -- Build the strategy, don't just relay numbers

Read `references/strategy-framework.md` and synthesize across every
section of the generated report into a tiered plan: quick wins (decommission
waste this month), rightsizing (this quarter), commitment strategy (RI/SP
coverage target with payback period), and governance gaps (tagging,
budgets, anomaly detection) that compound savings over time. Always cite
the actual numbers from the report -- never invent a savings estimate Cost
Explorer didn't return.

### Step 3 -- Flag what's missing, don't guess

If Reservation/Savings Plans utilization came back empty, that means the
account has no RIs/SPs (or Cost Explorer access wasn't granted) -- say so
explicitly rather than assuming full on-demand pricing is a deliberate
choice. If Trusted Advisor checks are absent, note that a support-plan
upgrade would unlock more checks rather than omitting the topic entirely.

## Output

`reports/output/cost-optimization.{md,html,pdf}` plus your synthesized
strategy (add it as a final section to the same report, or as a separate
`cost-optimization-strategy.md` if the user wants the raw evidence and the
strategy kept separate).

## Quality checks

1. Every dollar figure and percentage in your strategy write-up traces back
   to a specific number in the generated report -- no invented estimates.
2. The strategy is tiered (quick win vs. quarter-scale vs. ongoing
   governance), not a flat list of every finding in discovery order.
3. If `--compute-optimizer-regions` wasn't scoped to match where the
   account's actual compute lives, say so -- Compute Optimizer results are
   per-region and an empty result set from the wrong region reads
   identically to "no opportunities found."
