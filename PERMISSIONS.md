# Required AWS permissions

**Every skill in this plugin is read-only.** No script calls a
`Create*`, `Put*`, `Update*`, `Delete*`, `Modify*`, `Attach*`, `Authorize*`,
`Purchase*`, or `Terminate*` API. The only two exceptions, both opt-in and
clearly called out where they appear, are:

- `wellarchitected:UpdateAnswer` in `shared/awslib/collectors/well_architected.py`
  -- only invoked if you explicitly ask the `aws-well-architected-review`
  skill to persist findings back into a real Well-Architected Tool workload.
  It is never called automatically.
- CloudWatch Logs Insights `StartQuery` -- this creates a query execution
  (a read operation against your data, billed like any Logs Insights query)
  but does not modify infrastructure.

**Grant the credentials you use with this plugin read-only access.** The
credential chain is whatever `boto3`/the AWS CLI resolves normally (a named
profile, SSO session, environment variables, or an instance/task role) --
this plugin does not manage credentials itself, so scope them down at the
IAM level before pointing any skill at an account you care about.

## Option A -- fastest: AWS managed `ReadOnlyAccess`

Attach the AWS-managed `arn:aws:iam::aws:policy/ReadOnlyAccess` policy to
the IAM user/role/profile you'll run this plugin as. It covers every
service below with room to spare and requires no maintenance as AWS adds
actions.

## Option B -- least privilege: scoped custom policy

If your organization requires a tighter policy, everything below is
everything the collectors in `shared/awslib/collectors/` call. Attach as a
customer-managed policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CoreDescribeListGet",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "elasticloadbalancing:Describe*",
        "autoscaling:Describe*",
        "ecs:List*",
        "ecs:Describe*",
        "eks:List*",
        "eks:Describe*",
        "rds:Describe*",
        "dynamodb:List*",
        "dynamodb:Describe*",
        "elasticache:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "s3:List*",
        "s3:GetBucket*",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetReplicationConfiguration",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:Describe*",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListDashboards",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "route53:ListHealthChecks",
        "route53:GetHealthCheckStatus",
        "route53:ListHostedZones",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IamReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListAccessKeys"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityServices",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
        "securityhub:DescribeStandardsControls",
        "accessanalyzer:ListAnalyzers",
        "accessanalyzer:ListFindings",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CostAndOptimization",
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "ce:GetCostForecast",
        "ce:GetReservationUtilization",
        "ce:GetReservationCoverage",
        "ce:GetSavingsPlansUtilization",
        "ce:GetSavingsPlansCoverage",
        "ce:GetRightsizingRecommendation",
        "ce:GetSavingsPlansPurchaseRecommendation",
        "ce:GetReservationPurchaseRecommendation",
        "ce:GetAnomalies",
        "compute-optimizer:GetEC2InstanceRecommendations",
        "compute-optimizer:GetEBSVolumeRecommendations",
        "support:DescribeTrustedAdvisorChecks",
        "support:DescribeTrustedAdvisorCheckResult",
        "budgets:ViewBudget",
        "servicequotas:GetServiceQuota",
        "servicequotas:GetAWSDefaultServiceQuota",
        "servicequotas:ListRequestedServiceQuotaChangeHistory"
      ],
      "Resource": "*"
    },
    {
      "Sid": "WellArchitectedReadOnly",
      "Effect": "Allow",
      "Action": [
        "wellarchitected:ListWorkloads",
        "wellarchitected:GetWorkload",
        "wellarchitected:ListAnswers",
        "wellarchitected:ListLensReviewImprovements"
      ],
      "Resource": "*"
    },
    {
      "Sid": "BackupReadOnly",
      "Effect": "Allow",
      "Action": [
        "backup:ListBackupPlans",
        "backup:GetBackupPlan",
        "backup:ListBackupVaults",
        "backup:ListProtectedResources",
        "backup:ListBackupJobs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OrganizationsReadOnly",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "organizations:ListPolicies",
        "organizations:ListTargetsForPolicy",
        "organizations:ListDelegatedAdministrators",
        "guardduty:ListOrganizationAdminAccounts",
        "securityhub:ListOrganizationAdminAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

Notes on Option B:

- `support:Describe*` requires a **Business, Enterprise On-Ramp, or
  Enterprise Support plan** -- on Basic/Developer support the calls fail
  with `SubscriptionRequiredException`, which the cost-optimization skill
  already handles gracefully (it just omits that section from the report).
- `wellarchitected:UpdateAnswer` is **deliberately omitted** from this
  policy. If you want the WA review skill to be able to write evidence back
  into a real workload, add that action yourself as a separate, explicit
  decision -- do not add it by default.
- Cost Explorer (`ce:*`) and Well-Architected Tool APIs are only callable
  from `us-east-1` regardless of which region you're analyzing; the scripts
  already pin those clients to `us-east-1` internally.
- `s3:GetBucketLocation` is listed explicitly (though the `s3:GetBucket*`
  wildcard above already covers it) because the S3 collector depends on it
  structurally: it resolves each bucket's own region first, then routes that
  bucket's per-bucket calls through a client in that region. Without it,
  every bucket outside the scanned region fails with `PermanentRedirect`.

## Verifying before you run a review

```bash
aws sts get-caller-identity --profile <profile>
aws iam simulate-principal-policy \
  --policy-source-arn <your-role-or-user-arn> \
  --action-names ec2:DescribeVpcs guardduty:ListDetectors ce:GetCostAndUsage \
  --profile <profile>
```
