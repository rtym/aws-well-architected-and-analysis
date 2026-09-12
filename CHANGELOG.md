# Changelog

Notable changes to this plugin. Versions track `.claude-plugin/plugin.json`.

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
