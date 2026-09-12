---
name: aws-well-architected-review
description: >
  Perform an AWS Well-Architected Framework review across the six pillars
  (Operational Excellence, Security, Reliability, Performance Efficiency,
  Cost Optimization, Sustainability) by collecting real evidence from an
  AWS account via boto3 (the same credential chain the AWS CLI uses) and
  scoring each pillar's best-practice questions against that evidence.
  Use this skill when someone asks for a "well-architected review",
  "WAFR", "WA Tool review", "pillar review", "architecture review against
  AWS best practices", mentions a specific pillar ("security pillar
  review", "cost pillar review", "reliability review"), or asks to "dive
  into the AWS account" and assess it against AWS's own framework. Can
  optionally cross-reference a real workload already defined in the
  account's AWS Well-Architected Tool console.
---

# AWS Well-Architected Review

Reviews an AWS account against the AWS Well-Architected Framework
(https://wa.aws.amazon.com/wat.map.en.html): six pillars, each with a set
of best-practice questions. This skill deliberately separates **evidence
collection** (the CLI script, deterministic, testable) from **judgment**
(you, reading the evidence against the question catalogue and forming a
risk-rated verdict) -- don't skip straight to writing findings without
reading both.

Read-only. See `${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy.

## Before you start

1. Confirm scope with the user: which pillar(s) (default: all six),
   which region(s) (default: the profile's configured region), and whether
   they have an existing AWS Well-Architected Tool workload to
   cross-reference (`--workload-id`).
2. Load the question catalogue for every pillar in scope --
   these are the actual AWS Well-Architected Framework best-practice
   questions, not something to improvise:

```
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/references/pillars/security.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/references/pillars/reliability.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/references/pillars/performance-efficiency.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/references/pillars/cost-optimization.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/references/pillars/operational-excellence.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/references/pillars/sustainability.md
```

Each file maps every question ID (e.g. `SEC04`, `REL11`, `COST07`) to
exactly which piece of evidence in the collection script answers it, and
which questions simply **aren't API-observable** and must be asked about
directly rather than guessed at.

## Workflow

### Step 1 -- Collect evidence

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/aws-well-architected-review/scripts/collect_evidence.py \
  --profile <profile> \
  --pillar all \
  --regions us-east-1 \
  --json-out reports/output/wa-evidence.json \
  --output-dir reports/output \
  --formats md,html,pdf
```

Use `--pillar security` (etc.) to scope to one pillar; use `--workload-id`
if the user has an existing WA Tool workload and wants improvement items
already logged there cross-referenced against your findings.

This produces an **evidence pack**, not a findings report -- it's raw
counts and resource lists organized by pillar, plus an explicit prompt at
the top of the report reminding you (or whoever reads it) that judgment is
the next step.

### Step 2 -- Score each question

For every question in scope, read the corresponding evidence and the
pillar reference's "what to flag" guidance, then decide: **Yes** (best
practice followed), **Partial**, **No**, or **Not verified via API** (ask
the user directly for process/organizational questions -- do not mark
these compliant by default). Cite the specific resource IDs from the
evidence pack for every non-"Yes" answer.

### Step 3 -- Risk-rate and write findings

Use AWS's own risk taxonomy: **High Risk Issue (HRI)** or **Medium Risk
Issue (MRI)** per question, same as the real WA Tool. A "No" on a
foundational practice (e.g. SEC02 -- no MFA on console users, REL11 -- no
Multi-AZ on a production database) is typically an HRI; a "Partial" on a
nice-to-have optimization is typically an MRI.

### Step 4 -- (Optional) Write back to a real workload

Only if the user explicitly asks: use
`shared.awslib.collectors.well_architected.update_answer()` to record your
scored answers against a real WA Tool workload. This mutates account
state (adds `wellarchitected:UpdateAnswer` to the IAM footprint) -- never
call it without being asked, and confirm the workload ID with the user
first.

### Step 5 -- Deliver

Produce a findings report (Markdown/HTML/PDF, same `Report` class as the
evidence pack) organized by pillar -> question -> verdict -> risk rating ->
recommendation. If the user also ran `aws-security-review` or
`aws-architecture-discovery`, cross-reference those reports instead of
re-deriving the same facts.

## Output

- `reports/output/well-architected-evidence.{md,html,pdf}` (Step 1)
- A findings report you author in Step 3-5, in the same three formats,
  using `shared.reporting.report.Report` directly (see any skill's
  `scripts/*.py` for the pattern) or by hand in Markdown if the review is
  narrowly scoped and a full script run is overkill.

## Quality checks

1. Every question ID in scope from the pillar reference appears in the
   final findings report -- don't silently skip ones without clean
   evidence; mark them "Not verified via API" instead.
2. Every "No" or "Partial" verdict cites a specific resource ID, count, or
   quote from the evidence pack -- no unsupported assertions.
3. Process-only questions (OPS01-03, OPS05, OPS07, OPS10-11, SEC10-11,
   REL08, REL12, COST10-11) are never marked "Yes" without the user having
   actually confirmed the practice -- these cannot be inferred from AWS
   API state alone.
