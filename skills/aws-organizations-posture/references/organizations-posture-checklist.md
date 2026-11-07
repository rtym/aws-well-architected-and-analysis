# Organizations posture checklist

## What "good" looks like

- **SCPs attached at the OU level**, not scattered per-account -- easier to
  reason about and audit than hundreds of individual account attachments.
  The report's coverage check follows inheritance (root, then each OU down
  to the account), so OU-level attachments count as coverage.
- **A dedicated security-tooling delegated administrator account** (often
  called "Security" or "Audit" in AWS's multi-account guidance) registered
  as the GuardDuty and Security Hub administrator, so every member account
  is auto-enrolled and centrally visible -- rather than each account team
  enabling (or forgetting to enable) these services independently.
- **A baseline SCP** applied at the root or every OU that at minimum
  prevents disabling GuardDuty/Security Hub/Config/CloudTrail, leaving the
  organization's own root user unusable, and restricts regions to the ones
  actually approved for use.
- **Account status hygiene** -- SUSPENDED accounts should be understood
  (deliberately retired vs. an unexpected billing/compliance issue) rather
  than silently present in the account list.

## What to flag

- No delegated administrator for GuardDuty or Security Hub -- means
  detection coverage depends on every individual account team remembering
  to turn these on, which reliably degrades over time as new accounts are
  created.
- Accounts with no restrictive SCP in effect at any level -- the report
  lists them directly; each one has no guardrail beyond its own IAM.
- A very large, flat SCP structure (e.g. the same one policy attached to
  every account individually rather than at the root/OU) -- a maintenance
  and drift risk, not a security gap per se, but worth mentioning.
- Member accounts still on the default `FullAWSAccess` SCP with nothing
  more restrictive attached anywhere in their OU hierarchy -- means no
  organizational guardrails exist at all for that account.

## Framing recommendations

When recommending an SCP or delegated-admin change, note that these are
organization-wide changes with real blast radius -- unlike this plugin's
other skills, this is prescriptive advice about changes a human should
review and apply deliberately, not something to imply is a quick fix.
Always mention that SCP changes should be tested in a non-production OU or
via a dry-run/simulation approach before wide rollout.
