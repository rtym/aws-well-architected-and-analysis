# Operational Excellence Pillar

Design principles: perform operations as code, make frequent small
reversible changes, refine operations procedures frequently, anticipate
failure, learn from all operational failures.

| Q# | Question | Evidence to pull from this account | Where in the evidence pack |
|----|----------|--------------------------------------|------------------------------|
| OPS01 | How do you determine what your priorities are? | Not API-observable; ask about business/compliance drivers | Direct question |
| OPS02 | How do you structure your organization to support your business outcomes? | Not API-observable (org design); ask about team/account ownership model | Direct question |
| OPS03 | How does your organizational culture support your business outcomes? | Not API-observable | Direct question |
| OPS04 | How do you design your workload so that you can understand its state? | AWS Config recorder actually running (not just rule compliance), resource tagging for ownership/environment | `Security.ConfigRecorder.Recording`, `ConfigRuleCompliance`, tag sampling across collected resources |
| OPS05 | How do you reduce defects and improve flow into production? | Not directly observable; ask about CI/CD, IaC (CloudFormation/Terraform/CDK) usage | Direct question -- note whether resources look hand-created (inconsistent naming/tagging is a tell) |
| OPS06 | How do you mitigate deployment risks? | ECS/EKS deployment configuration (rolling vs. blue/green), ASG instance refresh config | `EcsClusters[]._Services[].deploymentConfiguration` |
| OPS07 | How do you know that you are ready to support a workload? | Runbook/on-call existence -- not API-observable | Direct question |
| OPS08 | How do you utilize workload observability in your organization? | CloudWatch alarms/dashboards actually configured, and whether alarms have any notification action attached (a decorative alarm with no action is a common gap) | `Observability.Alarms`, `Observability.AlarmsWithNoActions`, `Observability.Dashboards` |
| OPS09 | How do you understand the health of your operations? | Same evidence as OPS08, framed as ongoing operational visibility rather than one-time setup | `Observability.Alarms`, `Observability.AlarmsInAlarmState` |
| OPS10 | How do you manage workload and operations events? | GuardDuty/Security Hub as one event source; ask about incident/event management tooling (EventBridge rules, SNS topics) | `GuardDutyFindings`, `SecurityHubFindings` |
| OPS11 | How do you evolve operations? | Not API-observable; ask about retrospective/post-incident review practice | Direct question |

## How to use this pillar's evidence

Operational Excellence is the pillar with the fewest AWS-API-observable
signals -- most of its best practices are about process, not
infrastructure. Be explicit in the report about which questions were
answered from evidence versus which require a conversation with the
account owner, and never mark a process-only question "compliant" just
because no negative evidence was found.
