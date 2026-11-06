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

## Control IDs for the deterministic checks

The scan's own deterministic checks (run directly against the APIs, not
via Security Hub) each correspond to a Security Hub control -- cite the ID
so the writeup is audit-ready even when Security Hub itself is off.
Verified against the Security Hub controls documentation on 2026-11-06,
except IAM.3's exact wording (older source; the 90-day threshold is also
CIS's):

| Report section / finding               | Control | Suggested severity |
| -------------------------------------- | ------- | ------------------ |
| Publicly restorable EBS snapshot       | EC2.1   | CRITICAL           |
| Default security group with rules      | EC2.2   | LOW (MEDIUM if instances use it) |
| Unencrypted EBS volume                 | EC2.3   | MEDIUM             |
| EBS encryption-by-default off          | EC2.7   | MEDIUM             |
| Instance allowing IMDSv1               | EC2.8   | HIGH               |
| Publicly shared RDS snapshot           | RDS.1   | CRITICAL           |
| Publicly accessible RDS instance       | RDS.2   | CRITICAL           |
| RDS storage not encrypted              | RDS.3   | MEDIUM             |
| Account-level Block Public Access off  | S3.1    | MEDIUM (HIGH with public buckets present) |
| KMS key rotation disabled              | KMS.4   | MEDIUM             |
| Access key older than 90 days          | IAM.3   | MEDIUM             |
| Lambda URL with auth type NONE         | --      | HIGH (no stable control ID; the public resource policy behind it is flagged by Lambda.1) |

A publicly restorable snapshot (EBS or RDS) is a complete, out-of-band
copy of the data: treat it at the same severity as a public S3 bucket
even though no "breach" has been observed.
