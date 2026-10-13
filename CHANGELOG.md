# Changelog

Notable changes to this plugin. Versions track `.claude-plugin/plugin.json`.

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
