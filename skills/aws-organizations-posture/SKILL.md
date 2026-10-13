---
name: aws-organizations-posture
description: >
  Assess AWS Organizations posture: whether this account is even part of an
  organization, what member accounts exist and their status, Service
  Control Policy coverage per account, delegated administrator accounts,
  and whether GuardDuty/Security Hub are centrally managed org-wide versus
  configured independently per account -- then render a Markdown/HTML/PDF
  report. Use this skill when someone asks for a "multi-account review",
  "organizations posture", "SCP audit", "check our AWS Organizations
  setup", "is GuardDuty centrally managed", "delegated administrator
  review", or asks about account structure/governance across a multi-
  account AWS estate. Complements `aws-security-review`, which assesses a
  single account's posture in depth.
---

# AWS Organizations Posture

Assesses the account-structure and governance layer that sits above any
single account's security/cost/architecture posture: is this a multi-
account estate, are Service Control Policies actually attached where they
should be, and are GuardDuty/Security Hub managed centrally (one delegated
admin, every member auto-enrolled) or ad hoc per account. Read-only. See
`${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy -- note this
skill additionally needs `organizations:*` read actions, which only work
from the management account or a delegated administrator.

## Before you start

Confirm with the user which identity/profile you're using -- this only
produces meaningful output run against the **management account** or an
account **delegated as an administrator** for Organizations. Warn them
up front if they're unsure, since a plain member account will correctly
report "not part of an organization" (or hit AccessDenied on most calls)
and that's not a bug, it's the expected result for the wrong account.

Load the checklist:

```
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-organizations-posture/references/organizations-posture-checklist.md
```

## Workflow

### Step 1 -- Run the collector

```bash
${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script ${CLAUDE_PLUGIN_ROOT}/skills/aws-organizations-posture/scripts/analyze_organization.py \
  --profile <profile> \
  --region us-east-1 \
  --json-out reports/output/organizations-evidence.json \
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

`--region` here only picks which region to call the (regional)
GuardDuty/Security Hub `ListOrganizationAdminAccounts` APIs from --
Organizations itself is global.

### Step 2 -- Read the report correctly

- **"Not part of an organization"** is a valid, common result for a
  standalone account -- don't treat it as an error, and don't recommend
  joining an Organization unless the user is actually asking about
  multi-account governance.
- **"Accounts without a directly-attached SCP"** is a lead to verify, not
  a confirmed gap -- the collector only checks direct account-level policy
  attachments; an account can still be covered by a policy attached at its
  OU or the root. Say this explicitly and offer to check OU-level
  attachments if the user wants that level of confirmation.
- **No GuardDuty/Security Hub delegated administrator** means every member
  account is on its own for enabling and configuring those services --
  this is usually worth flagging even if individual accounts look fine
  today, since it's how coverage gaps silently appear as new accounts are
  created.

### Step 3 -- Cross-reference with per-account reviews

If the user has also run `aws-security-review` or
`aws-well-architected-review` against specific member accounts, note where
an account-level finding (e.g. GuardDuty not enabled) is actually a
symptom of the org-wide gap (no delegated admin / no SCP mandating it)
rather than an isolated one-account oversight.

## Output

`reports/output/organizations-posture.{md,html,pdf}`.

## Quality checks

1. The report states plainly, in the first section, whether this account
   is or isn't an Organizations member -- never buries that.
2. "Without a directly-attached SCP" findings are phrased as something to
   verify against OU/root attachments, not asserted as gaps.
3. GuardDuty and Security Hub delegated-admin status are reported
   independently -- one being centrally managed doesn't imply the other is.
