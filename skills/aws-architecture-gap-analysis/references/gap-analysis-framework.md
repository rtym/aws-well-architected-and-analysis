# Gap analysis synthesis framework

## Categories

- **Architectural gap** -- a structural weakness in how the system is put
  together: missing redundancy (single NAT Gateway, single-AZ RDS),
  missing fault isolation (one security group shared across tiers that
  should be isolated), a data store reachable directly from an
  internet-facing subnet, no backup/DR path.
- **Security issue** -- a control gap or active finding: GuardDuty/Security
  Hub disabled, an active finding, IAM hygiene gap, unencrypted data.
- **Both** -- most of the highest-value findings land here. A security
  group open to `0.0.0.0/0` on a database port is simultaneously an
  architectural fault-isolation failure and a security control gap; report
  it once, tagged with both categories, not twice.

## Merging duplicate signals across inputs

The same underlying fact often surfaces from more than one upstream skill.
Before writing a gap entry, check:

| If you see... | ...also check for the same fact in |
|---|---|
| A wide-open security group in the discovery inventory | `aws-security-review`'s `WideOpenSecurityGroupRules` section (same data, already formatted) |
| An RDS instance with `MultiAZ: false` | Well-Architected REL11 evidence |
| A single NAT Gateway per VPC | Well-Architected REL02/REL10/REL11 evidence |
| An unencrypted or public S3 bucket | `aws-security-review`'s S3 Exposure section |
| GuardDuty/Security Hub not enabled | Well-Architected SEC04 evidence |
| Idle/unattached resources | Both `aws-cost-optimization` and Well-Architected COST04/SUS02 evidence |

Merge these into one gap entry that cites every source it appeared in --
this is also a good sanity check that the underlying evidence is
consistent across reports (if two sources disagree, investigate why before
reporting either).

## Prioritization: blast radius x likelihood

Rank gaps by combining:

1. **Blast radius** -- how much of the system (data tier vs. one dev
   instance), how many users, whether it's the production or a lower
   environment.
2. **Likelihood** -- an actively exploited/observed issue (a live GuardDuty
   finding) ranks above a theoretical gap (no MFA, but no evidence of
   attempted use); a public-internet-facing gap ranks above one requiring
   prior internal network access.

State this reasoning inline for at least the top 5 gaps -- a sorted table
alone doesn't show the user *why* item 1 outranks item 2.

## Recommendation format

Each recommendation states:

- **The fix**, specific enough to execute without further research (name
  the resource, the config change).
- **Effort**: quick config change (minutes-hours) / requires a change
  window (needs testing/rollback plan) / requires a redesign (multi-sprint,
  needs its own design work).
- **Impact**: which pillar(s)/risk(s) it retires, and roughly how much of
  the gap's severity it resolves (a full fix vs. a partial mitigation).
- **Sequencing**: if this recommendation depends on another one landing
  first (e.g. "enable Security Hub" precedes "action Security Hub CIS
  findings"), say so explicitly and order the report's recommendation list
  accordingly.
