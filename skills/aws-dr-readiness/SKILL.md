---
name: aws-dr-readiness
description: >
  Assess disaster-recovery readiness: AWS Backup plan/vault coverage and
  cross-region copy configuration, RDS Multi-AZ/read-replica/global-cluster
  topology, S3 cross-region replication, and Route 53 health checks (DNS
  failover readiness) -- mapped against AWS's own DR strategy tiers
  (backup & restore, pilot light, warm standby, multi-site active-active)
  -- then render a Markdown/HTML/PDF report. Use this skill when someone
  asks for "DR readiness", "disaster recovery review", "backup coverage
  check", "RTO/RPO assessment", "are we ready for a region failure", "check
  our backup posture", or "cross-region replication review". Deepens the
  REL09/REL13 evidence the `aws-well-architected-review` Reliability
  pillar only summarizes.
---

# AWS Disaster Recovery Readiness

Assesses whether an account's actual DR posture (backups, replication,
failover mechanisms) matches what it *should* be for the recovery
objectives that matter to the business -- not just whether backups exist,
but whether they're configured the way the desired RTO/RPO requires.
Read-only. See `${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy.

## Before you start

1. Load the DR strategy tiers reference -- you need this to translate raw
   evidence (backup plans, replica counts) into a recovery-time/recovery-
   point conversation, not just a resource inventory:

   ```
   view ${CLAUDE_PLUGIN_ROOT}/skills/aws-dr-readiness/references/dr-strategy-tiers.md
   ```

2. **Ask the user what their actual RTO/RPO targets are, or whether they
   even have documented ones**, before assessing "readiness" -- a
   single-AZ RDS instance with daily backups is a legitimate, sufficient
   choice for a workload with a 24-hour RPO target and no HA requirement.
   Don't default to recommending the most resilient (and most expensive)
   tier for every workload; match the recommendation to the stated
   requirement, and say so explicitly when no requirement has been stated.

## Workflow

### Step 1 -- Run the collector

```bash
${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script ${CLAUDE_PLUGIN_ROOT}/skills/aws-dr-readiness/scripts/dr_readiness.py \
  --profile <profile> \
  --regions us-east-1,eu-west-1 \
  --json-out reports/output/dr-evidence.json \
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

This produces: AWS Backup plan/vault/cross-region-copy coverage, an RDS
DR-signal chart (single-AZ vs. read-replicas vs. cross-region/global
clusters), S3 replication status, and Route 53 health check inventory.

### Step 2 -- Map evidence to a DR tier, per workload if the user can identify them

Using the strategy-tiers reference, place what you found against the tier
it actually implements today (often it's a mix -- some workloads at
"backup & restore," others at "warm standby"). Don't assume the whole
account is uniformly at one tier.

### Step 3 -- Call out the gaps AWS Backup coverage numbers hide

A high `ProtectedResourceCount` doesn't mean the *right* resources are
covered -- cross-reference against an `aws-architecture-discovery` run if
available to check whether production-tagged resources specifically are
protected, not just that *some* resources are.

### Step 4 -- Recommend proportionate to stated requirements

If no RTO/RPO target was given, present the current posture mapped to a
tier and ask what target the business actually needs before recommending
changes -- don't recommend upgrading everything to warm standby/multi-site
by default, since that's a real cost and complexity tradeoff the user
should decide on, not something to assume.

## Output

`reports/output/dr-readiness.{md,html,pdf}`.

## Quality checks

1. Every recommendation is tied to a stated (or explicitly-asked-about)
   RTO/RPO target -- never assumes "more resilient is always better."
2. "Unreplicated S3 buckets" and similar findings are framed as prompts to
   confirm intent per-resource, not a blanket gap (some data genuinely
   doesn't need cross-region replication).
3. If Route 53 health checks are absent, the report asks whether failover
   is handled another way before calling it a gap.
