# Changelog

Notable changes to this plugin. Versions track `.claude-plugin/plugin.json`.

## [1.7.0] - 2026-11-12

### Fixed
- A denied API call no longer scores as a result. Collectors return the same empty value when a call is denied as when there is nothing to find, and the checks scored that value as written. A role without `ec2:DescribeVolumes` passed "every EBS volume is encrypted"; one without `guardduty:ListDetectors` failed "GuardDuty is enabled" and raised a false "exposure without GuardDuty" attack path; one without the AWS Backup actions was told it had no backup plan. These checks now report NO DATA, with a note that says why, and stay out of the score.
- A region-wide security check passes only when every scanned region was read. One unread region used to be skipped, so the check passed "in every scanned region" on the strength of the others.
- An S3 bucket whose Block Public Access or encryption settings can't be read (a bucket policy, a missing `s3:Get*` permission) is no longer listed as public or unencrypted. The evidence names it under `BucketsNotRead`, and the two bucket checks report NO DATA when unread buckets are all that stands between them and a pass.
- Macie's "not enabled" answer (an `AccessDeniedException` with that message) still reads as off. Any other denial from Macie is now treated as a denial.
- The security report's evidence tables show "unknown" where a call was denied, instead of a zero or "NO -- gap": the encryption and threat-finding counts, the CloudTrail summary, and the account-level Block Public Access line. Buckets the scan couldn't read are counted above the S3 table.
- A KMS key whose own policy denies the scan was skipped without a trace. It is now recorded, and the rotation check reports NO DATA for it.
- A failed check carries its "partial" note whenever part of its evidence was denied, including when the unread region added nothing to the count.
- A scan that is denied a call it can't work without (security groups, instances, the IAM credential report), or whose credentials don't resolve, stops with one line naming the call and exit code 2 instead of a traceback.
- The network traffic scan stops the same way when the log group doesn't exist, and its report has an Incomplete Queries section when a flow-log query timed out or failed. Those sections used to read as "no such traffic".
- A TCP listener on port 443 is no longer flagged as unencrypted: that is TLS passthrough on a Network Load Balancer.
- The IAM credential report is given up to a minute to generate. Ten seconds was too short for accounts with many users, and the scan failed with `ReportInProgress`.
- DR findings for single-AZ databases name the region the database is in; every one used to read as "global".
- The security report's priority list is called "the ten most important fixes" only when it holds ten.

### Added
- Every denied call is recorded on the `AwsContext` (`ctx.denied`) and saved in the evidence as `AccessDenied`: collector, operation, region, error code, and the resource for per-bucket denials.
- An **Access Gaps** section in every report lists the denied calls, so an empty table can be told apart from one the scan couldn't fill. In the organizations report it shows whether "not part of an organization" was a denied call or a standalone account. The security report's executive summary says how many checks dropped out because of them.
- The security report's Detection Coverage table shows "unknown" for a service whose status call was denied, and the detection-coverage KPI leaves it out. The DR report shows "n/a" for backup KPIs it couldn't read and marks its backup counts as a lower bound.
- `shared/analysis/access.py`, and 91 tests in `tests/test_access_denied.py` covering the path from the denied call to the report.

## [1.6.0] - 2026-11-07

### Removed
- The `aws-lucid-diagrams` skill, its icon-and-layout guide, and the Lucid MCP setup steps in the README. Architecture diagrams still come from `aws-architecture-discovery`, as Mermaid in its report.

### Changed
- `diagram-conventions.md` moved to `skills/aws-architecture-discovery/references/`, the only skill that still draws diagrams, and lost its Lucid-specific lines. The four rules are unchanged.

## [1.5.0] - 2026-11-07

### Added
- Scored analysis layer (`shared/analysis/`): checks report PASS, FAIL, or NO DATA. The score is passed ÷ checks with data, the method Security Hub uses for its security score. Includes a per-area breakdown and one prioritized action list.
- Security review:
  - 31 checks mapped to Security Hub controls, with severities verified against the controls reference (EC2.19 high-risk ports, EC2.18, Config.1 and others).
  - Six attack-path correlations: an internet-reachable IMDSv1 instance, a public instance with a high-risk port, a public unencrypted database, exposure without GuardDuty, threats without an audit trail, and public buckets with no account-level backstop.
  - Threat triage, an executive summary, and priority actions.
  - `--json-out` now carries an `Analysis` block.
- DR readiness: seven scored readiness checks mapped to REL questions, plus an ordered fix list.
- Well-Architected evidence pack: the security checks run per SEC question.
- Every report now has KPI tiles. Cost adds rightsizing savings, month-over-month change on complete months, and a stacked trend chart. Discovery adds a region × resource matrix.

### Changed
- Report design:
  - A cover header with the plugin version, a score ring and meters, and KPI tiles.
  - A table of contents; in the PDF it shows page numbers.
  - Page footers, severity and status labels, dark mode in HTML, and a phone layout.
- Markdown keeps severities as plain words.
- Charts are now SVG and follow one visual system:
  - single-series bars use one color, and severity bars use severity colors;
  - value labels and integer ticks;
  - donuts fold small segments into Other.
- WeasyPrint no longer logs CSS warnings: browser-only rules are left out of the PDF.

### Fixed
- Wide PDF tables no longer overflow the page or split words mid-word.
- Access Analyzer evidence now records the analyzers, so zero findings from zero analyzers is NO DATA, not a pass.

### Tests
- Suite 628 → 811 tests, line coverage still 100%. New tests cover the engine, every check, the attack paths, scorecard and KPI escaping, and PDF rendering with no WeasyPrint warnings.

### Fixed (found while building 1.5.0)
- Cost Explorer's rightsizing type is `TERMINATE`/`MODIFY` (upper case); the new savings estimate matches that, verified against the botocore model.

### Docs
- Updated the security, DR, cost, WA, and gap-analysis skill guides.
- Rewrote the severity reference around the verified Security Hub control severities, including a correction: EC2.2 is HIGH, not LOW.
- Added CONTRIBUTING guidance on adding a scored check.
- Added the new verified sources to SOURCES.md.

## [1.4.1]

### Fixed

- **The least-privilege policy granted nothing for IAM Access Analyzer.**
  `PERMISSIONS.md` listed `accessanalyzer:ListAnalyzers` and
  `accessanalyzer:ListFindings`, using the boto3 client name instead of the
  IAM prefix `access-analyzer`, so under Option B the Access Analyzer
  section was always empty. A new test (below) now catches this class of
  mistake.
- **Security scans crashed when run from a region other than the
  CloudTrail trail's home region.** `GetTrailStatus` was called with the
  trail name, which raises `TrailNotFoundException` for a shadow trail and
  for an organization trail seen from a member account. It now uses the
  trail ARN, and an unresolvable trail is recorded with unknown status
  instead of aborting the scan.
- **DR readiness crashed on accounts with calculated Route 53 health
  checks** (the usual building block of DNS failover): Route 53's status
  API rejects them. They are now listed without a status.
- **GuardDuty findings included archived ones.** `ListFindings` returns
  archived findings unless filtered, and suppression rules archive
  findings automatically, so the report resurfaced noise the account owner
  had silenced. Findings are now unarchived only and requested most severe
  first, so the 200-finding cap drops the least severe.
- **GuardDuty attack-sequence findings (severity 9.0-10.0) were labelled
  HIGH.** They now get GuardDuty's documented CRITICAL band. The two
  scripts that each carried a copy of the thresholds share one function.
- **Access Analyzer missed unused-access and internal-access findings**,
  which only `ListFindingsV2` returns. The report table now shows each
  finding's type and resource.
- **Silent truncation in five collectors:** Cost Explorer
  `GetCostAndUsage` (no botocore paginator; pages split inside a period are
  now merged), `GetRightsizingRecommendation` and `GetAnomalies`
  (paginators existed but went unused), and both Compute Optimizer
  recommendation calls (`nextToken` was never followed).
- **ECS inventory failed with more than 100 clusters in a region**
  (`DescribeClusters` takes at most 100); calls are now batched.
- **ACM expiry checks skipped ECDSA and RSA 3072/4096 certificates**:
  `ListCertificates` returns only RSA_1024 and RSA_2048 by default.
- **False positives:**
  - HTTP listeners that only redirect to HTTPS (the recommended setup,
    FSBP ELB.1) were reported as plaintext listeners.
  - Instances with the metadata endpoint disabled, and terminated
    instances, were reported as allowing IMDSv1.
  - Every Aurora and Multi-AZ DB cluster member was reported as a
    single-AZ instance; those are now judged at the cluster level, with a
    separate table for single-AZ clusters.
  - KMS keys with imported or custom-key-store material, which can't
    rotate automatically, were reported under KMS.4.
- **The Organizations SCP check measured the wrong thing.** It counted
  only SCPs attached directly to an account, and counted the allow-all
  `FullAWSAccess` that AWS attaches to every account by default, so a
  typical organization always reported full coverage. It now computes
  effective coverage through root and OU inheritance (nested OUs
  included), ignores `FullAWSAccess`, and leaves out the management
  account, to which SCPs never apply. Needs two more read-only actions:
  `organizations:ListAccountsForParent` and
  `organizations:ListOrganizationalUnitsForParent`.
- Security Hub findings in workflow state NOTIFIED (owner told, issue
  still open) were filtered out along with resolved ones.
- Public RDS snapshot checks (RDS.1) covered DB snapshots only, missing
  Aurora and Multi-AZ DB cluster snapshots.
- A CloudTrail posture of "a multi-region trail exists" plus "some trail
  is logging" read as compliant even when the multi-region trail was
  stopped. Both reports now state whether one trail is multi-region *and*
  logging (CloudTrail.1).
- Security-group rules for all traffic rendered their port range as
  "None-None"; they now read "all".
- Logs Insights polling didn't treat `Timeout` as a terminal state and
  waited out the full local timeout.
- Since 1.4.0 the security scan reads RDS; a credential without RDS access
  aborted the scan. The RDS describe calls now degrade like the rest.
- The account ID is fetched once per run instead of once per region.

### Changed

- **Dependency floors raised** to the current releases: boto3 and botocore
  >=1.43.126, Markdown >=3.11.3, pytest >=9.2.0, ruff >=0.17.4.
- **Python 3.14** joins the CI matrix, and `bin/run-skill-script` now
  tries `python3.14` first (it previously never looked for it, so a
  machine with only 3.14 installed was told no suitable Python existed).
- `make` targets re-sync `.venv` whenever a requirements file changes.
  The local venv had drifted below the requirement floors (boto3 1.43.93
  against a floor of 1.43.122), so local runs weren't testing what CI
  tests.
- README: the CI description named a stale `ruff --select F` gate; it now
  describes the rule set in `pyproject.toml`.

### Tests

- New `tests/test_permissions.py` statically finds every AWS API call in
  the collectors (126 distinct operations) and checks that `PERMISSIONS.md`
  grants each one, that every action uses a real IAM prefix, and that
  every explicit action names a real operation. Verified to fail on the
  original `accessanalyzer:` prefix and on a removed action.
- Regression tests for every fix above, a drift test tying the launcher's
  interpreter list to the CI matrix, a multi-VPC topology test (each
  resource drawn under its own VPC only), and an in-process run of each
  script's `__main__` entry point.
- Suite grows 457 -> 628; line coverage of `shared/` and `skills/` is
  now 100% (2,074 statements), up from 99%.

## [1.4.0]

### Added

- **The security review checks nine more exposure and encryption gaps**,
  each mapped to its Security Hub control ID in
  `skills/aws-security-review/references/severity-and-standards.md`:
  publicly restorable EBS snapshots (EC2.1), default security groups that
  allow traffic (EC2.2), unencrypted EBS volumes (EC2.3), EBS
  encryption-by-default off per region (EC2.7), publicly shared RDS
  snapshots (RDS.1), publicly accessible RDS instances (RDS.2),
  unencrypted RDS storage (RDS.3), the account-level S3 Block Public
  Access backstop (S3.1), customer-managed KMS keys with rotation off
  (KMS.4), and Lambda function URLs with auth type NONE. The report gains
  Encryption Posture, RDS Exposure, Lambda Function URLs Without
  Authentication, and Default Security Groups Allowing Traffic sections.
- **Inspector and Macie enablement** now appear beside GuardDuty,
  Security Hub, and the Config recorder in the Regional Coverage table,
  so all five detection services are confirmed per region.
- `PERMISSIONS.md` least-privilege policy gained the matching actions:
  `ec2:GetEbsEncryptionByDefault`, `inspector2:BatchGetAccountStatus`,
  `macie2:GetMacieSession`, `kms:ListKeys`, `kms:DescribeKey`,
  `kms:GetKeyRotationStatus`, `s3:GetAccountPublicAccessBlock`.
- 22 new tests cover every added check (moto where it implements the API,
  `botocore.stub.Stubber` where it doesn't -- moto ignores
  `describe_snapshots` server-side filters, so that contract is pinned
  with a stub). Suite grows 435 -> 457; the changed collector modules sit
  at 100% line coverage.

### Changed

- **IAM access-key findings now apply the 90-day rotation threshold**
  (FSBP IAM.3). Previously every active key with a rotation date was
  listed under "access keys to review", which buried the stale ones; now
  only keys older than 90 days (or with an unparseable rotation date) are
  reported, with their age in days.

### Verified

- The Well-Architected pillar references were re-checked against AWS's
  announcements: the April 2025 framework refresh (which 1.2.0 already
  incorporated) is still the current core framework; AWS's November 2025
  Well-Architected additions are new AI/ML *lenses*, which sit outside
  the six-pillar core framework this plugin reviews against.

## [1.3.0]

### Added

- **Licensing of contributions and reuse is now explicit.**
  `CONTRIBUTING.md` opens with a Licensing section: contributions are
  accepted under the repository's MIT license (inbound = outbound), and
  reuse of the code elsewhere -- including public code indexes and
  reference corpora -- is welcome as long as the copyright notice is kept
  and the repo is attributed. The README carries an MIT license badge.

### Changed

- **Runtime dependency floors raised via Dependabot** (second batch, every
  bump merged through a pull request with the full CI gate green):
  boto3 >=1.43.122, matplotlib >=3.11.2, PyYAML >=6.0.3,
  Pygments >=2.21.0, Markdown >=3.11.2. No functional changes to the
  collectors, reports, or skills.

## [1.2.1]

### Changed

- **Dependency floors raised via Dependabot** (its first batch after being
  enabled in 1.2.0, every bump merged through a pull request with the full
  CI gate green). Runtime: botocore >=1.43.121, WeasyPrint >=70.0. Dev:
  ruff >=0.17.3, pytest-cov >=7.1.0, moto >=5.2.5. CI actions: checkout,
  setup-python and upload-artifact moved to their current major versions.
  No functional changes to the collectors, reports, or skills.

## [1.2.0]

### Fixed

- **The Well-Architected pillar references were stale against the current
  framework.** Verified every pillar's question set against the 2025-02-25
  AWS framework documentation (URLs in `SOURCES.md`): Performance
  Efficiency was rewritten -- AWS restructured it so PERF03 covers all data
  management, PERF04 networking, and PERF05 is a process question the old
  file didn't have; OPS04 is now "How do you implement observability in
  your workload?"; OPS05 gained "ease remediation"; SUS02 is now "How do
  you align cloud resources to your demand?"; REL04/REL05 use the full
  "design interactions in a distributed system" wording. PERF05 joined the
  process-only list the review skill must never mark "Yes" from API
  evidence alone.
- The cost report labelled Reserved Instance `UnusedHours` as a dollar
  amount; it is a count of hours. It now reports utilization %, unused
  hours, and `NetRISavings` (the actual dollar figure) separately.
- The cost report printed the raw Savings Plans utilization dict into the
  report body; it now reports the utilization percentage, unused
  commitment, and net savings from the real response shape.
- The organizations report said "Master account"; AWS's current term is
  "management account" (the API field keeps its old name).
- `aws-architecture-discovery/SKILL.md` had a garbled sentence about
  `--all-regions` API costs left over from an incomplete edit.

### Added

- **A plugin-wide writing-style reference**
  (`skills/aws-architecture-gap-analysis/references/writing-style.md`):
  plain voice, a banned-filler vocabulary, numbers over adjectives, bold
  for labels only, an orientation opening for every artifact, and a legend
  for any severity/priority codes used. Every skill loads it, and a test
  keeps it that way.
- **Every generated report now opens with an orientation paragraph**
  (`Report(intro=...)`): what the report is, what it covers, where to
  start reading.
- **Severity legends** (`severity_legend()`): reports that use severity
  levels define each level used -- and only those -- next to the findings.
- **A deterministic prose lint** (`shared/reporting/prose_lint.py`, CLI
  `bin/lint-report-prose <dir>`): banned filler, unfilled template
  placeholders, duplicated lines, duplicate headings, missing orientation
  paragraph; code fences and table rows (quoted AWS data) are exempt. Runs
  over every skill's rendered report and the plugin's own documentation in
  `tests/test_prose_quality.py`, with negative tests proving each rule
  fires.
- **Coverage raised from 93% to 98% of `shared/` + `skills/` lines**
  (suite 361 -> 431 tests), closing the untested seams the existing suite
  surrounded: every script's `collect()` orchestration (which collector
  runs per region vs. once, and under which evidence key its result lands
  -- the JSON contract `aws-architecture-gap-analysis` reads), the DR
  report's cross-region backup merge, root-account risk detection and
  `collect_global_security()`, Security Hub status/finding-cap paths, EKS
  nodegroup enrichment, ELBv2 target-group/listener and ACM certificate
  enrichment, Trusted Advisor's category filter and missing-support-plan
  degradation, the Logs Insights polling loop, the organizations posture
  wiring and mixed-account-status report branches, GuardDuty severity
  band boundaries, the populated branch of every cost-report section, and
  the unexpected-error propagation paths (S3 bucket helpers,
  `is_organizations_member`). A new structural test also fails on any
  broken relative Markdown link in the repo's docs. `make cov` runs the
  suite with the coverage report (`pytest-cov` added to dev
  requirements).
- **A test dashboard on every CI run.** The test job now writes JUnit and
  coverage XML, and `.github/scripts/test_summary.py` (stdlib-only,
  unit-tested in `tests/test_ci_summary.py`) renders them onto the
  workflow run's summary page: pass/fail/skip counts per Python version,
  total line coverage with the least-covered files, and the full detail
  of every failure (`--maxfail=1` dropped so a red run shows all of them,
  not just the first). Raw XML is uploaded as a per-version artifact, and
  the README carries the workflow status badge.
- **A pull-request template** (`.github/PULL_REQUEST_TEMPLATE.md`) walking
  the contributor through the repo's tested invariants (read-only rule,
  escaping contract, degradation pattern, per-layer tests, changelog), and
  **Dependabot** (`.github/dependabot.yml`) for weekly pip and GitHub
  Actions updates, with minor/patch Python bumps grouped into one PR so
  boto3's near-daily releases don't flood the repo.

## [1.1.3]

### Fixed

- **Evidence collection and cost analysis crashed in accounts with no Savings
  Plans.** Cost Explorer answers `GetSavingsPlansUtilization` (and its other
  utilization, coverage, recommendation and forecast endpoints) with
  `DataUnavailableException` when there is simply no data -- no Savings Plans
  or reservations, or a brand-new account. `ignore_access_denied` did not
  recognise that code, so it aborted `collect_evidence.py` and
  `analyze_cost.py`. It is now treated as "no evidence" and the collector
  returns its empty default; other errors still propagate.

### Added

- Tests that every optional Cost Explorer collector, `collect_cost_report`,
  and both scripts' `collect()` survive `DataUnavailableException`.

## [1.1.2]

### Fixed

- **Skills failed on a fresh marketplace install.** Every SKILL.md ran a bare
  `python script.py`, which fails where only `python3` exists (stock macOS)
  and fails with `No module named 'boto3'` because nothing had installed
  `requirements.txt`. Skills now run their scripts through the new
  `bin/run-skill-script`, which finds a Python 3.11+ interpreter, creates a
  private virtualenv on first use (rebuilt when `requirements.txt` changes),
  and gives an install hint when no suitable Python is found.
- Missing Pango (needed by WeasyPrint for PDF export) now raises a clear
  error naming the fix and the `--formats md,html` fallback, instead of a raw
  `OSError` traceback.

### Added

- Tests that every SKILL.md script invocation goes through the launcher and
  that the launcher is executable.

## [1.1.1]

### Fixed

- **Installing from GitHub failed** with "Marketplace file not found":
  `.claude-plugin/marketplace.json` had never been committed. It is now part
  of the repo, and its plugin entry is named `aws-well-architected-and-analysis`
  to match `plugin.json`.
- README install instructions now cover adding the repo as a marketplace from
  GitHub, and the example entry for listing the plugin in another marketplace
  uses a valid GitHub source instead of a stale local path.

## [1.1.0]

### Added

- Tests pinning the diagram contract: no unlabelled edge is ever emitted,
  subnet Public/Private/Isolated classification follows the route tables
  (including the main-table fallback and IPv6 default routes), the legend
  lists exactly the symbol kinds drawn, generated Mermaid is structurally
  valid (balanced subgraphs, no edge to an undeclared node), labels cannot
  break out of their quotes, and both diagramming skills still load the
  shared conventions document.

### Changed

- **Diagram conventions are now enforced across both diagramming skills.**
  A new shared reference,
  `skills/aws-lucid-diagrams/references/diagram-conventions.md`, defines four
  rules that `aws-lucid-diagrams` and `aws-architecture-discovery` both load:
  every relationship carries its real connectivity detail (destination range,
  route table, protocol/port, direction), abbreviations are expanded and
  unmeasurable adjectives cut, labels stay to one clause, and every diagram
  ends with a legend inventorying the symbols it used and what each means.
- **`vpc_topology_mermaid()` rewritten** to implement those rules for the
  generated per-region topology diagram. It now reads route tables to
  classify each subnet as Public, Private or Isolated and labels the edge
  with the route that justifies it (`0.0.0.0/0 via rtb-0a1: outbound only,
  replies allowed`); draws VPC endpoints, VPC peering connections and Transit
  Gateway attachments, each labelled with its protocol or attachment id;
  writes full service names instead of `IGW`/`NAT`; puts the public internet
  and out-of-region peers in an "Outside this region" box; and appends a
  legend listing only the symbol kinds actually on the canvas, with counts.
- `aws-lucid-diagrams` gained Lucid-specific guidance for labelled connectors
  (label placement clearance, arrowheads matching traffic direction) and for
  building the legend container, plus quality checks and visual-re-check
  items covering both.

## [1.0.0]

First stable release. Promotes the 0.2.0 feature set -- nine skills, the
shared collector layer, and Markdown/HTML/PDF reporting -- to 1.0 with no
functional changes: the full CI gate (256 tests, `ruff`, byte-compile, and a
`--help` smoke test of every skill script) passes clean, and the read-only
API contract and HTML-escaping contract are settled enough to commit to
semantic versioning from here.

### Fixed

- `.gitignore` excluded a tracked source file. The report-basename patterns
  are deliberately unanchored so a stray `--output-dir` anywhere in the repo
  is still ignored, but `cost-optimization.*` also matched
  `skills/aws-well-architected-review/references/pillars/cost-optimization.md`.
  Skill reference content is never generated output, so it is now re-included
  explicitly.

### Changed

- `.gitignore` also covers virtualenv, editor, coverage, and build-artifact
  paths alongside the existing report and evidence rules.

## [0.2.0]

### Added

- **`aws-organizations-posture` skill** -- multi-account posture: Organizations
  membership, Service Control Policy coverage per account, delegated
  administrators, and whether GuardDuty/Security Hub are managed org-wide
  rather than configured per account.
- **`aws-dr-readiness` skill** -- AWS Backup plan/vault coverage and
  cross-region copy, RDS Multi-AZ/replica/global-cluster topology, S3
  cross-region replication, and Route 53 health checks, mapped against AWS's
  four DR strategy tiers.
- **`aws-lucid-diagrams` skill** -- draws AWS architecture diagrams in
  Lucidchart via the Lucid MCP connector using the real AWS 2024 icon set,
  with a self-check visual pass on the exported PNG before handoff.
- New collectors wired into the existing skills: CloudTrail posture, AWS
  Config recorder status, AWS Backup, AWS Budgets, Service Quotas, CloudWatch
  alarms/dashboards, ACM certificates, ELB listener TLS, and EC2 IMDSv2
  enforcement.
- `CONTRIBUTING.md` documenting the plugin's invariants (read-only rule,
  HTML-escaping contract, collector and testing patterns).
- `pyproject.toml` centralizing ruff and pytest config so local runs match CI.

### Fixed

- **Stored XSS in generated HTML reports.** Report content carries live AWS
  metadata (bucket names, tags, IAM usernames, Well-Architected workload
  names) that a limited-privilege principal can set to arbitrary text. Table
  cells, report title/subtitle/meta, and section headings are now HTML-escaped;
  the `<title>` element sink is closed too.
- **S3 collection crashed on multi-region accounts.** Per-bucket calls were
  pinned to one region, raising `PermanentRedirect` for any bucket elsewhere.
  Each bucket's region is now resolved and its calls routed accordingly.
- **Security Hub and Organizations crashes.** `InvalidAccessException` (Hub not
  subscribed) and `AccessDeniedException` (locked-down member account) weren't
  handled, aborting entire collection runs instead of degrading.
- **Cost windows used local dates.** Cost Explorer interprets `TimePeriod` in
  UTC; `date.today()` returned the machine's local date, silently shifting the
  billing window by a day for users far enough east or west of UTC.
- **GuardDuty findings were under-reported** -- `list_findings` read only the
  first page per detector.
- `expiring_certificates()` excluded already-expired certificates from the
  "expiring" set.
- `resolve_regions()` returned `[]` for a whitespace-only `--regions` value,
  crashing callers on `regions[0]`.
- Chart helpers crashed on empty, all-zero, or mismatched-length inputs.
- Seven Cost Explorer functions returned `[]` on access-denied while typed and
  consumed as dicts.
- `report.save()` had no defense against a path-traversal `basename`.

### Changed

- Test suite grown from 72 to 256 tests, adding end-to-end `main()` coverage
  for every skill script and structural integrity checks for every `SKILL.md`.
- CI runs Python 3.11/3.12/3.13, gates on `ruff`, and installs the HarfBuzz
  subsetting library WeasyPrint needs.
- `.gitignore` now covers every report basename wherever it lands, not just
  the default output directory.

## [0.1.0]

Initial release: six skills (`aws-well-architected-review`,
`aws-cost-optimization`, `aws-security-review`, `aws-architecture-discovery`,
`aws-architecture-gap-analysis`, `aws-network-traffic-analysis`), the shared
boto3 collector layer, Markdown/HTML/PDF reporting with charts, and a
GitHub Actions test workflow.
