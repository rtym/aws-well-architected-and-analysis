# Changelog

Notable changes to this plugin. Versions track `.claude-plugin/plugin.json`.

## [Unreleased]

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
