# Severity model and standards mapping

## Severity scales in play

This skill surfaces findings from two services with different native
severity scales -- normalize them in your write-up rather than presenting
raw numbers to the user without context.

**GuardDuty** returns a `Severity` float from 1.0 to 10.0. This skill
buckets it on GuardDuty's documented bands:

- `9.0 - 10.0` -> **CRITICAL** (attack-sequence findings from GuardDuty
  Extended Threat Detection: several correlated signals that together
  indicate an attack in progress or recently completed)
- `7.0 - 8.9` -> **HIGH**
- `4.0 - 6.9` -> **MEDIUM**
- `< 4.0` -> **LOW**

The collector requests only **unarchived** findings, most severe first.
GuardDuty's API returns archived findings too unless filtered, and
suppression rules archive findings automatically -- so archived findings
are noise the account owner already chose to silence.

**Security Hub** returns a `Severity.Label` directly:
`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFORMATIONAL`.

The collector only pulls Security Hub findings already filtered to
`CRITICAL`/`HIGH` and `RecordState: ACTIVE`, `WorkflowStatus: NEW` or
`NOTIFIED` (notified means the owner was told but the issue is still
open) -- resolved or suppressed findings won't appear, and MEDIUM/LOW Security Hub
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

- `AttackSequence:*` -- a multi-stage attack GuardDuty assembled from
  correlated signals (always CRITICAL). Read the finding's own timeline
  and MITRE ATT&CK mapping in the JSON evidence before writing it up.

Treat any `AttackSequence:`/`Trojan:`/`Backdoor:`/`CryptoCurrency:`
finding as needing immediate escalation regardless of the numeric
severity score.

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

## Control IDs and severities for the deterministic checks

The scan's own checks (`shared/analysis/security_checks.py`) run directly
against the APIs, not through Security Hub, so the report is audit-ready
even when Security Hub is off. Each check uses the severity of the
Security Hub control it implements. The severities below were verified
against the Security Hub controls reference on 2026-11-07. "(related)"
means the check tests the same risk more narrowly than the control: for
example, Config.1 also requires the service-linked role, and the check
only confirms the recorder is recording.

| Check | Control | Severity |
| ----- | ------- | -------- |
| Config recorder recording in every region | Config.1 (related) | CRITICAL |
| Root user has no access key | IAM.4 | CRITICAL |
| Root user has MFA | IAM.9 | CRITICAL |
| No high-risk port open to 0.0.0.0/0 or ::/0 | EC2.19 | CRITICAL |
| No publicly restorable EBS snapshot | EC2.1 | CRITICAL |
| No publicly shared RDS snapshot (DB or cluster) | RDS.1 | CRITICAL |
| No publicly accessible RDS instance | RDS.2 | CRITICAL |
| GuardDuty enabled in every region | GuardDuty.1 | HIGH |
| Multi-region trail logging | CloudTrail.1 (related) | HIGH |
| Amazon Inspector active | Inspector.1 (related) | HIGH |
| Internet-open rules only on ports 80/443 | EC2.18 | HIGH |
| Default security groups allow no traffic | EC2.2 | HIGH |
| Every instance requires IMDSv2 | EC2.8 | HIGH |
| Every bucket blocks public access | S3.8 | HIGH |
| No Lambda URL with auth type NONE | Lambda.1 (related) | HIGH (plugin-assigned; Lambda.1 itself is CRITICAL) |
| Amazon Macie enabled | Macie.1 | MEDIUM |
| Console users have MFA | IAM.5 | MEDIUM |
| No active access key older than 90 days | IAM.3 | MEDIUM |
| Account password policy set | IAM.7 (related) | MEDIUM |
| Listeners use TLS or redirect to HTTPS | ELB.1 (related) | MEDIUM |
| No ACM certificate expiring within 30 days | ACM.1 (related) | MEDIUM |
| Account-level S3 Block Public Access fully on | S3.1 | MEDIUM |
| EBS encryption by default on | EC2.7 | MEDIUM |
| Every EBS volume encrypted | EC2.3 (related) | MEDIUM |
| Every RDS instance encrypted | RDS.3 | MEDIUM |
| KMS key rotation on | KMS.4 | MEDIUM |
| Log file validation on every trail | CloudTrail.4 | LOW |

Checks with no Security Hub control carry a plugin-assigned severity:
Security Hub enabled (MEDIUM), no active IAM Access Analyzer findings
(MEDIUM), an Access Analyzer analyzer in every region (LOW; an
organization analyzer in another account also covers it), and S3 default
encryption (LOW; S3 has encrypted new objects by default since January
2023).

EC2.19's high-risk ports are 20, 21, 22, 23, 25, 110, 135, 143, 445,
1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5500, 5601, 8080, 8088,
8888, 9200, and 9300. EC2.18 with its default parameters allows only TCP
80 and 443 to be open to the world.

The listener check flags HTTP listeners that don't redirect to HTTPS and
TCP listeners, except a TCP listener on port 443: that is how a Network
Load Balancer passes TLS through to targets that terminate it themselves.

A publicly restorable snapshot (EBS or RDS) is a complete, out-of-band
copy of the data: treat it at the same severity as a public S3 bucket
even though no "breach" has been observed.

## The posture score

Score = passed checks / (passed + failed checks). Checks with no data are
left out, as Security Hub leaves out controls with no data. That includes
checks whose evidence the scan was denied (the report's Access Gaps
section lists the calls). A check fails when any resource in any scanned
region fails it, and passes only when every scanned region was read. Severity does not weight
the score: an account can score 90 with one CRITICAL failure, which is why
the report always shows the critical and high counts next to it. Bands:
90+ Strong, 70-89 Fair, 50-69 Weak, below 50 Poor.
