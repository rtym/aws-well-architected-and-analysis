# AWS Well-Architected & Analysis

A Claude Code plugin for analyzing AWS accounts: Well-Architected Framework
reviews, cost optimization, security posture, architecture discovery and
gap analysis, VPC network traffic analysis, multi-account Organizations
posture, disaster-recovery readiness, and polished Lucid diagrams -- each
backed by a tested Python collection layer and Markdown/HTML/PDF reporting
with charts.

> **Read-only by design.** Every skill in this plugin only calls
> `Describe*`/`List*`/`Get*` AWS APIs. **Grant the credentials you use with
> this plugin read-only access** (see [PERMISSIONS.md](PERMISSIONS.md)) --
> nothing here needs write access to your AWS account to function.

## What's inside

| Skill | Directory | What it does |
|---|---|---|
| `aws-well-architected-review` | `skills/aws-well-architected-review/` | Collects evidence across all six Well-Architected pillars and scores best-practice questions against it |
| `aws-cost-optimization` | `skills/aws-cost-optimization/` | Cost Explorer trends, RI/Savings Plans coverage, rightsizing, idle-resource waste, and a prioritized savings strategy |
| `aws-security-review` | `skills/aws-security-review/` | GuardDuty, Security Hub, IAM Access Analyzer, AWS Config, IAM hygiene, S3 exposure, wide-open security groups |
| `aws-architecture-discovery` | `skills/aws-architecture-discovery/` | Full infrastructure inventory (VPC/network, compute, containers, data stores) with Mermaid topology diagrams -- every edge labelled with its route/protocol, plus a legend |
| `aws-architecture-gap-analysis` | `skills/aws-architecture-gap-analysis/` | Synthesizes the other skills' output into one prioritized gap analysis |
| `aws-network-traffic-analysis` | `skills/aws-network-traffic-analysis/` | VPC Flow Logs (via CloudWatch Logs Insights) + GuardDuty network findings: top talkers, rejected traffic, port-scan heuristic, anomalies |
| `aws-lucid-diagrams` | `skills/aws-lucid-diagrams/` | Draws polished AWS architecture diagrams in Lucidchart (via the Lucid MCP connector) using real AWS service icons, laid out to minimize crossings, with a self-check visual pass before handoff |
| `aws-organizations-posture` | `skills/aws-organizations-posture/` | Multi-account posture: Organizations membership, SCP coverage, delegated administrators, whether GuardDuty/Security Hub are managed org-wide |
| `aws-dr-readiness` | `skills/aws-dr-readiness/` | AWS Backup coverage, RDS Multi-AZ/replica/global-cluster topology, S3 replication, Route 53 health checks -- mapped against AWS's DR strategy tiers |

Every skill's `SKILL.md` lists its own trigger phrases and workflow in
detail -- this README covers installation and setup only.
[CONTRIBUTING.md](CONTRIBUTING.md) documents the invariants for extending
the plugin (the read-only rule, the HTML-escaping contract, collector and
testing patterns). See
[SOURCES.md](SOURCES.md) for the public AWS documentation consulted while
building the reference content (Well-Architected pillars, VPC Flow Logs
format, GuardDuty finding types, DR strategy tiers), with a clear split
between pages actually fetched this session and long-standing content
drawn from general knowledge of AWS's public docs.

## Architecture

```
.
├── .claude-plugin/plugin.json     # plugin manifest
├── shared/
│   ├── awslib/
│   │   ├── session.py             # AwsContext: boto3 session/client management, pagination, access-denied handling
│   │   ├── cli.py                 # shared argparse scaffolding for every skill's CLI script
│   │   └── collectors/            # one module per AWS service area: vpc, compute, containers,
│   │                               #   data_stores, cost, security, network_traffic, cloudtrail,
│   │                               #   observability, quotas, backup, dr, organizations,
│   │                               #   well_architected
│   └── reporting/
│       ├── charts.py               # matplotlib chart helpers -> base64 PNG data URIs
│       ├── report.py               # Report class -> Markdown / HTML / PDF (via WeasyPrint)
│       └── jsonutil.py             # JSON serialization for raw boto3 evidence dumps
├── skills/<skill-name>/
│   ├── SKILL.md                    # what Claude reads when the skill triggers
│   ├── references/                 # question catalogues, frameworks, setup guides
│   └── scripts/*.py                # the actual CLI collector + report builder
├── tests/                          # pytest + moto/botocore.stub coverage for every collector and script
├── pyproject.toml                  # ruff + pytest config (shared by local runs and CI)
├── Makefile                        # make setup / test / lint / check
└── .github/workflows/tests.yml     # CI: lint, byte-compile, pytest, and every script's --help
```

Every skill's CLI script is a thin, independently runnable Python program
(`python skills/<name>/scripts/<script>.py --help`) -- Claude invokes it as
a subprocess, reads the JSON evidence it can optionally emit
(`--json-out`), and reasons over both the rendered report and the raw
JSON. The `shared/` layer is what makes this testable: collectors are
pure functions over an `AwsContext`, mockable with `moto` (EC2, IAM, S3,
ECS, DynamoDB, ...) or `botocore.stub.Stubber` (Cost Explorer, GuardDuty,
Security Hub, Access Analyzer, Config, Well-Architected Tool -- services
`moto` doesn't fully cover yet).

## Installing the plugin

This is a standard Claude Code plugin directory (a `.claude-plugin/plugin.json`
manifest with `skills/` auto-discovered underneath), and the repo doubles as
its own marketplace via `.claude-plugin/marketplace.json`. To install it from
GitHub:

```bash
# from inside Claude Code:
/plugin marketplace add rtym/aws-well-architected-and-analysis
/plugin install aws-well-architected-and-analysis@aws-well-architected-and-analysis
```

Or from a local clone:

```bash
/plugin marketplace add /path/to/aws-well-architected-and-analysis
/plugin install aws-well-architected-and-analysis@aws-well-architected-and-analysis
```

To list it in another marketplace (for example your org's own), add an entry
that points at this repo:

```json
{
  "name": "aws-well-architected-and-analysis",
  "source": { "source": "github", "repo": "rtym/aws-well-architected-and-analysis" },
  "description": "AWS account analysis: Well-Architected reviews, cost, security, architecture discovery/gap analysis, network traffic, Organizations posture, DR readiness, and Lucid diagrams."
}
```

After installing, reload Claude Code (or restart the session) for the
skills to be picked up.

### Python environment

The skill scripts need Python 3.11+ and the packages in `requirements.txt`
(`boto3`, `matplotlib`, `markdown`, `weasyprint`). You don't install these by
hand: every skill runs its script through `bin/run-skill-script`, which on
first use creates a private virtualenv and installs `requirements.txt` into it.
That takes about a minute; later runs reuse it, and it is rebuilt automatically
when `requirements.txt` changes. The virtualenv lives outside the plugin
directory so plugin updates don't discard it -- in `$CLAUDE_PLUGIN_DATA` when
Claude Code provides it, otherwise `~/.cache/aws-well-architected-and-analysis/`
(set `AWS_WAA_VENV` to choose another path).

The only prerequisite is a Python 3.11+ interpreter on `PATH`
(`python3.13`, `python3.12`, `python3.11` or `python3`). macOS's built-in
`/usr/bin/python3` is 3.9 and isn't enough -- `brew install python@3.12`.

WeasyPrint (used for PDF export) needs a few system libraries beyond pip
(Pango/Cairo plus HarfBuzz's subsetting library). On Debian/Ubuntu -- the
same set CI installs:

```bash
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libharfbuzz-subset0 libffi-dev shared-mime-info
```

On macOS: `brew install pango`. If PDF export isn't needed, Markdown and
HTML output work with just `boto3`/`matplotlib`/`markdown` installed --
every script's `--formats` flag defaults to `md,html,pdf` but accepts any
subset, e.g. `--formats md,html`.

### AWS credentials and permissions

**Grant read-only access.** These scripts use `boto3`, which resolves
credentials exactly the way the AWS CLI does -- a named profile
(`--profile`), an SSO session, environment variables, or an instance/task
role. Scope whichever identity you point this plugin at down to read-only
*before* running any skill against an account you care about:

- **Fastest:** attach the AWS-managed `ReadOnlyAccess` policy.
- **Least privilege:** see [PERMISSIONS.md](PERMISSIONS.md) for the exact
  scoped JSON policy covering only the actions these collectors call.

The one narrow exception -- `wellarchitected:UpdateAnswer`, which writes
scored answers back into a real AWS Well-Architected Tool workload -- is
never called automatically; it only runs if you explicitly ask the
`aws-well-architected-review` skill to persist findings, and it isn't
included in the least-privilege policy by default. Add it yourself as a
deliberate, separate decision if you want that capability.

### Lucid MCP (optional, for `aws-lucid-diagrams`)

That one skill needs the Lucid MCP connector connected in your Claude Code
session. This is a user-side step Claude cannot complete on its own:

1. Run `/mcp` in Claude Code and select **"claude.ai Lucid"**.
2. **If it isn't listed**, the connector needs enabling first on the
   claude.ai side -- go to claude.ai's connector/integration settings,
   find "Lucid," and enable it there, then run `/mcp` again.
3. Selecting it runs an OAuth flow in your browser; once it reports
   success, the skill's full Lucid tool set becomes available for that
   session.

No setup is needed ahead of time beyond having a Lucid account -- the
skill checks connection status itself (via `ToolSearch("Lucid")`) and will
prompt for the steps above the first time it's used if Lucid isn't
already connected.

## Running the tests

```bash
make setup   # create the venv and install dev dependencies
make check   # lint + full suite + byte-compile + --help smoke (what CI gates on)
```

Or directly:

```bash
./.venv/bin/pip install -r requirements-dev.txt
./.venv/bin/python -m pytest
```

Tests never touch a real AWS account -- `moto` mocks EC2/IAM/S3/ECS/RDS/
DynamoDB, and `botocore.stub.Stubber` mocks the services `moto` doesn't
fully cover (Cost Explorer, GuardDuty, Security Hub, Access Analyzer,
Config, Well-Architected Tool).

The suite covers four layers:

| Layer | Files | What it guards |
|---|---|---|
| Collectors | `test_collectors_*.py` | Each AWS call's request shape, response parsing, and graceful degradation when a service is disabled or a permission is missing |
| Reporting | `test_reporting.py`, `test_jsonutil.py` | Chart rendering, Markdown/HTML/PDF output, and the HTML-escaping contract (see `CONTRIBUTING.md`) |
| Report assembly | `test_skill_scripts.py` | Each skill's `build_report()` against synthetic evidence |
| End-to-end + structure | `test_script_main.py`, `test_skill_integrity.py`, `test_cli.py`, `test_session.py` | Each script's `main()` writing real files; SKILL.md frontmatter, name/directory agreement, and that every `${CLAUDE_PLUGIN_ROOT}` path a skill references exists |

CI (`.github/workflows/tests.yml`) runs the full suite on Python 3.11,
3.12, and 3.13, byte-compiles every module, gates on `ruff check --select F`
(unused imports / undefined names), and checks that every skill's CLI
script exposes `--help` cleanly.

## Report output

Every skill writes to `reports/output/` by default (`--output-dir` to
change it) in Markdown, HTML, and PDF (`--formats` to pick a subset). Pass
`--json-out <path>` to any script to also keep the raw evidence as JSON --
recommended whenever you plan to run more than one skill in the same
session, since `aws-architecture-gap-analysis` and follow-up questions
read that JSON instead of re-querying AWS.

> **Generated reports contain real account data** -- account IDs, resource
> names and ARNs, IAM usernames, security findings, and (for `--json-out`)
> complete raw AWS API responses. `.gitignore` covers the default output
> directory and every report basename the skills emit, but treat these
> files as sensitive wherever they land: don't paste them into tickets or
> chats unreviewed, and don't commit them.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT -- see [LICENSE](LICENSE).
