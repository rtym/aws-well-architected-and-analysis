# Sources used to build this plugin

Public AWS documentation informed the reference content in `skills/*/references/`.
Two categories, kept distinct on purpose: pages actually fetched and read
during this build (verified against current AWS docs), versus content
drawn from general training knowledge of AWS's long-standing public
documentation but not independently re-fetched in this session. Treat the
second category as "should still match current AWS docs" rather than
"verified against them today" -- re-check before treating it as current if
AWS has since revised the relevant page.

## Fetched and read this session

| URL | Used for | Informs |
|---|---|---|
| https://wa.aws.amazon.com/wat.map.en.html | The six Well-Architected Framework pillars, their design-principle one-liners, and topic-area breakdown | `skills/aws-well-architected-review/references/pillars/*.md` |
| https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html | VPC Flow Logs default record field order/format, custom-format fields (`pkt-srcaddr`, `tcp-flags`, `flow-direction`, `traffic-path`, etc.) | `skills/aws-network-traffic-analysis/references/flow-logs-setup.md`, the canned Logs Insights queries in `shared/awslib/collectors/network_traffic.py` |
| https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html | Publishing flow logs to CloudWatch Logs (log group, IAM role, delivery latency) | `skills/aws-network-traffic-analysis/references/flow-logs-setup.md` |
| https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html | GuardDuty finding-type prefixes and examples relevant to network threats (`Recon:`, `UnauthorizedAccess:`, `Trojan:`, `Backdoor:`, `CryptoCurrency:`, `Impact:`, `Behavior:`) | `shared/awslib/collectors/network_traffic.py`'s `NETWORK_FINDING_TYPE_PREFIXES`, `skills/aws-network-traffic-analysis/references/detection-guide.md`, `skills/aws-security-review/references/severity-and-standards.md` |
| https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-options-in-the-cloud.html | The four DR strategy tiers (Backup & Restore, Pilot Light, Warm Standby, Multi-site Active/Active), their approximate RTO/RPO ranges, and the AWS services typically involved in each | `skills/aws-dr-readiness/references/dr-strategy-tiers.md` |

One fetch attempt did not return usable content and its claims were
**not** used: `https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-remediation.html`
(GuardDuty remediation guidance). The general incident-response guidance
in `skills/aws-network-traffic-analysis/references/detection-guide.md`
("Escalation guidance") is explicitly labeled there as general practice to
verify against your own IR plan, not an AWS documentation citation, for
this reason.

## Drawn from general knowledge of AWS's public documentation (not re-fetched this session)

These reflect long-standing, stable AWS documentation (service API
behavior, the Well-Architected Framework's specific per-pillar
best-practice question IDs like `SEC04`/`REL11`/`COST07`) that didn't
change materially in a way this build re-verified live. If AWS has since
restructured a pillar's questions or a service's API, these should be
re-checked against the source before being treated as current:

- The specific best-practice question IDs and their one-line descriptions
  within each pillar (`skills/aws-well-architected-review/references/pillars/*.md`)
  -- the pillar *list* and topic areas came from the fetched
  `wat.map.en.html` page above; the individual question numbering is from
  AWS's published pillar whitepapers.
- General AWS API shapes and parameters for the ~25 services this plugin's
  collectors call (`shared/awslib/collectors/*.py`) -- standard boto3/
  botocore behavior, cross-checked against real API responses via `moto`
  and `botocore.stub.Stubber` in the test suite rather than re-fetching
  API reference docs page by page.
- CIS AWS Foundations Benchmark / AWS Foundational Security Best Practices
  / PCI DSS as Security Hub standards, and their general purpose
  (`skills/aws-security-review/references/severity-and-standards.md`).

## Not sourced from the public internet

Everything else -- the shared `awslib`/`reporting` Python code, the report
templates, the chart styling, the gap-analysis synthesis framework, and
the plugin/skill structure itself -- was authored directly for this repo,
following the conventions of this organization's existing Claude Code
plugins (see `README.md`), not copied from an external source.
