---
name: aws-security-review
description: >
  Verify AWS security posture and find gaps: GuardDuty and Security Hub
  enablement + active findings, Security Hub standards compliance (CIS AWS
  Foundations, AWS Foundational Security Best Practices, PCI DSS), IAM
  Access Analyzer findings, AWS Config rule compliance and whether the
  Config recorder is even running, CloudTrail posture (multi-region trail,
  actively logging, log file validation), IAM hygiene (MFA, stale access
  keys, root account risk, password policy), public/unencrypted S3
  buckets, security groups open to 0.0.0.0/0 or ::/0, EC2 instances not
  enforcing IMDSv2, load balancer listeners without TLS, and ACM
  certificates expired or expiring within 30 days -- then produce a
  severity-ranked Markdown/HTML/PDF security report with charts. Use this
  skill when someone asks for a "security review", "security posture
  assessment", "check GuardDuty", "check Security Hub", "find security
  gaps", "IAM audit", "is this account secure", "security
  recommendations", "check CloudTrail", "check IMDSv2", or "compliance
  check" (CIS/PCI/FSBP).
---

# AWS Security Review

Verifies whether an account's core security *detection and prevention*
controls are actually turned on and clean -- not just theoretically
configured -- and surfaces concrete, resource-level gaps. Read-only. See
`${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy.

## Before you start

Load the finding-severity and standards reference:

```
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-security-review/references/severity-and-standards.md
```

Confirm scope with the user: profile/credentials, region(s) (GuardDuty,
Security Hub, Access Analyzer, and Config are all regional services --
default to the account's primary region(s), or `--all-regions` for a full
sweep).

## Workflow

### Step 1 -- Run the collector

```bash
${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script ${CLAUDE_PLUGIN_ROOT}/skills/aws-security-review/scripts/security_scan.py \
  --profile <profile> \
  --regions us-east-1,eu-west-1 \
  --json-out reports/output/security-evidence.json \
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

This produces: CloudTrail posture (multi-region trail, logging, log file
validation), IAM hygiene summary, S3 exposure, per-region GuardDuty/
Security Hub/Config-recorder enablement + finding counts, a severity-
distribution chart, the actual findings tables, Security Hub standards
coverage percentages, non-compliant Config rules, Access Analyzer active
findings, every security group rule open to the world, EC2 instances not
enforcing IMDSv2, load balancer listeners without TLS, and ACM
certificates expired or expiring within 30 days.

### Step 2 -- Triage before reporting

Not every returned finding is equally worth the user's attention. Prioritize:

1. **GuardDuty/Security Hub not enabled at all** in a region with live
   workloads -- this is a bigger gap than any individual finding, because
   it means detection coverage has a blind spot. Say this first.
2. **CRITICAL/HIGH severity active findings** -- read the full finding
   detail (title, resource, description) from the JSON evidence, not just
   the summary table, before writing a recommendation.
3. **Root account or MFA gaps** -- these are foundational; a single root
   access key or an admin console user without MFA outweighs a long tail
   of low-severity findings.
4. **Public/unencrypted S3 and wide-open security groups** -- concrete,
   fixable-today items; name the exact bucket/security-group ID.

### Step 3 -- Map to standards, don't just count findings

Use the standards reference to explain *why* a finding matters in terms of
CIS/FSBP/PCI control IDs where Security Hub already ties a finding to a
standard -- this gives the user an audit-ready narrative, not just a raw
finding list.

### Step 4 -- Recommend, with the exact remediation

Every finding in the final report should end with a concrete next action
(e.g. "restrict sg-0123abc's inbound rule on 22/tcp from 0.0.0.0/0 to the
corporate VPN CIDR" -- not "review security group rules"). If a control is
outright disabled (GuardDuty, Security Hub, MFA), the recommendation is to
enable it and which standard/detector to enable first.

## Output

`reports/output/security-review.{md,html,pdf}` -- if the user also wants
architectural or cost context, this skill's evidence pairs directly with
`aws-architecture-discovery` and `aws-well-architected-review`'s Security
pillar, and feeds `aws-architecture-gap-analysis`.

## Quality checks

1. GuardDuty/Security Hub enablement status is stated explicitly for every
   region in scope, even when both are enabled cleanly (absence of a
   negative finding is not the same as confirming the control is on).
2. Every HIGH/CRITICAL finding has a named resource and a specific
   remediation, not a generic "investigate this."
3. Findings already tied to a compliance standard by Security Hub cite
   that standard's control ID in the writeup.
4. IAM MFA/root-account/key-age findings are never omitted even if the
   headline GuardDuty/Security Hub numbers look clean -- IAM hygiene is
   checked independently of either detection service.
