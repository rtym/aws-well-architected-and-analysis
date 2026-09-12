# Security Pillar

Design principles: implement a strong identity foundation, enable
traceability, apply security at all layers, automate security best
practices, protect data in transit and at rest, keep people away from data,
prepare for security events.

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| SEC01 | How do you securely operate your workload? | AWS Config recorder actually recording; CloudTrail multi-region trail, actively logging, log file validation enabled; account contact info | `Security.ConfigRecorder`, `Global.CloudTrail` (`HasMultiRegionTrail`/`HasLoggingTrail`/`HasLogFileValidation`); account contact info isn't collected -- ask directly |
| SEC02 | How do you manage authentication for people and machines? | IAM credential report (MFA, key age), password policy, SSO/Identity Center use | `IamCredentialReport`, `IamFindings`, `IamPasswordPolicy` |
| SEC03 | How do you manage permissions for people and machines? | IAM Access Analyzer findings, attached policies, wildcard actions/resources | `AccessAnalyzerFindings`, `IamUsers[]._AttachedPolicies` |
| SEC04 | How do you detect and investigate security events? | GuardDuty enabled + findings, Security Hub enabled + findings, Config | `GuardDuty`, `GuardDutyFindings`, `SecurityHub`, `SecurityHubFindings` |
| SEC05 | How do you protect your network resources? | Security groups open to 0.0.0.0/0 or ::/0, NACLs, VPC endpoints vs. public routes | `WideOpenSecurityGroupRules`, `NetworkAcls`, `VpcEndpoints` |
| SEC06 | How do you protect your compute resources? | Instance metadata service v2 enforcement (per-instance); patch/AMI age still needs SSM data, not collected here -- flag as a gap | `Compute.InstancesAllowingImdsv1`; ask user for SSM Patch Manager status separately |
| SEC07 | How do you classify your data? | Resource tags (`Tags` fields on collected resources), S3 bucket naming/tag conventions | Cross-reference `Tags` across `Instances`, `S3Buckets`, `RdsInstances` |
| SEC08 | How do you protect your data at rest? | S3 default encryption, EBS encryption (`Volumes[].Encrypted`), RDS `StorageEncrypted` | `UnencryptedBuckets`, `Volumes`, `RdsInstances` |
| SEC09 | How do you protect your data in transit? | ALB/NLB listeners still on HTTP/TCP instead of HTTPS/TLS, ACM certificates expired or expiring within 30 days, RDS `require_secure_transport` (needs parameter group check, not collected) | `Compute.PlaintextListeners`, `Compute.ExpiringCertificates` |
| SEC10 | How do you anticipate, respond to, and recover from incidents? | GuardDuty/Security Hub as detection surface; ask user about runbooks (org-process, not API-observable) | `GuardDuty`, `SecurityHub` + a direct question to the user |
| SEC11 | How do you incorporate application security into your workload? | Not directly API-observable; ask about SAST/DAST/dependency scanning in the pipeline | Direct question to the user; note as a gap if unanswered |

## Review process notes

- Standards coverage (CIS AWS Foundations, AWS Foundational Security Best
  Practices, PCI DSS) comes from `SecurityHubStandardsSummary` --
  cite the exact enabled-control percentage per standard.
- Anything not observable through the AWS API (runbooks, SAST/DAST tooling,
  organizational security culture) must be asked about explicitly and
  marked "Not verified via API" rather than assumed compliant.
