# Severity model and standards mapping

## Severity scales in play

This skill surfaces findings from two services with different native
severity scales -- normalize them in your write-up rather than presenting
raw numbers to the user without context.

**GuardDuty** returns a `Severity` float from 0.1-8.9. This skill's
collector buckets it:

- `>= 7.0` -> **HIGH**
- `4.0 - 6.9` -> **MEDIUM**
- `< 4.0` -> **LOW**

**Security Hub** returns a `Severity.Label` directly:
`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFORMATIONAL`.

The collector only pulls Security Hub findings already filtered to
`CRITICAL`/`HIGH` and `RecordState: ACTIVE`, `WorkflowStatus: NEW` --
resolved or suppressed findings won't appear, and MEDIUM/LOW Security Hub
findings are intentionally out of scope for the default scan (there are
usually too many to be useful signal; note this to the user and offer to
widen the filter if they want full coverage).

## GuardDuty finding-type families worth naming explicitly

GuardDuty finding `Type` strings follow a `Category:ResourceType/ThreatName`
pattern. The families that matter most in a security review:

- `Recon:*` -- reconnaissance (port scanning, unusual API calls) --
  usually a precursor, not yet a compromise.
- `UnauthorizedAccess:*` -- credentials or infrastructure accessed from an
  unusual/known-malicious source.
- `Trojan:*` / `Backdoor:*` -- strong signal of actual compromise on the
  named resource.
- `CryptoCurrency:*` -- crypto-mining activity, usually indicates a
  compromised compute resource.
- `Policy:*` -- a policy violation (e.g. root credential usage) rather
  than an active threat -- still worth flagging, different urgency.

Treat any `Trojan:`/`Backdoor:`/`CryptoCurrency:` finding as needing
immediate escalation regardless of the numeric severity score.

## Security Hub standards in this report

`SecurityHubStandardsSummary` reports `EnabledControlCount` /
`ControlCount` per subscribed standard. Common standards and what a low
percentage typically means:

- **CIS AWS Foundations Benchmark** -- foundational account hygiene
  (root MFA, CloudTrail, password policy, security group hygiene). A low
  score here usually correlates directly with the IAM hygiene findings
  this skill also collects independently -- cross-reference them.
- **AWS Foundational Security Best Practices (FSBP)** -- AWS's own
  broadest baseline, service-by-service. This is normally the standard
  with the most controls; a low enabled-percentage here often just means
  the standard was recently turned on and controls haven't propagated --
  check `StandardsStatus` before assuming a genuine gap.
- **PCI DSS** -- only relevant if the account actually processes payment
  card data; don't recommend enabling it purely for completeness if the
  user confirms it doesn't apply.

A standard being *enabled* with a low *control-pass* percentage is a
different finding from a standard not being *enabled* at all -- state
which one you're reporting.
