---
name: aws-architecture-discovery
description: >
  Extract a full inventory of an AWS account's deployed infrastructure --
  VPCs, subnets, route tables, internet/NAT gateways, VPC endpoints, VPC
  peering, Transit Gateway attachments, security groups, NACLs, EC2
  instances, Auto Scaling groups, ELB/ALB/NLB, ECS clusters/services, EKS
  clusters/nodegroups, RDS, DynamoDB, ElastiCache, Lambda, and S3 -- then
  build architecture documentation from multiple viewpoints (network
  topology, compute/container topology, data tier) with Mermaid diagrams
  and a Markdown/HTML/PDF report. Use this skill when someone asks to
  "discover the architecture", "extract infrastructure inventory", "map
  the AWS account", "document the current deployment", "what's running in
  this account", "generate architecture diagrams from AWS", or "build an
  as-built architecture doc". This is the evidence-gathering foundation the
  `aws-architecture-gap-analysis` and `aws-well-architected-review` skills
  build on top of.
---

# AWS Architecture Discovery

Produces two things from a live (or moto-mocked, in CI) AWS account:

1. **A raw JSON inventory** (`--json-out`) -- the source of truth every
   other skill in this plugin reads instead of re-querying AWS.
2. **A Markdown/HTML/PDF report** with per-region resource-count charts, a
   security-groups-open-to-the-world callout, and a Mermaid VPC topology
   diagram per region.

Read-only: every AWS call is a `Describe*`/`List*`/`Get*` operation. See
`${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the exact IAM policy needed.

## Before you start

Load the resource taxonomy so you know which viewpoint each resource
belongs to and what a good architecture doc calls out, plus the diagram
conventions any diagram you hand-author has to follow:

```
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-architecture-discovery/references/viewpoints.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-lucid-diagrams/references/diagram-conventions.md
```

Confirm with the user (if not already stated):

1. **Profile / credentials** -- which AWS CLI profile or role to use.
2. **Scope** -- one region, a specific list, or `--all-regions` (every
   region enabled for the account). Default to the profile's configured
   region if the user doesn't say.
3. **Output location** -- default `reports/output/`; ask if they want it
   elsewhere.

## Workflow

### Step 1 -- Run the collector

```bash
${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script ${CLAUDE_PLUGIN_ROOT}/skills/aws-architecture-discovery/scripts/discover.py \
  --profile <profile> \
  --regions us-east-1,eu-west-1 \
  --json-out reports/output/architecture-inventory.json \
  --output-dir reports/output \
  --formats md,html,pdf
```

`run-skill-script` runs the script in the plugin's own Python virtualenv. On
first use it creates that virtualenv and installs `requirements.txt` (about a
minute; progress goes to stderr). If it exits saying Python 3.11+ is missing,
relay its install hint to the user rather than retrying. If only PDF export
fails (WeasyPrint needs Pango: `brew install pango` on macOS), the Markdown
and HTML reports are already written -- rerun with `--formats md,html` or
tell the user how to enable PDF.

Use `--all-regions` instead of `--regions` for a full account sweep. This
can take a while and rack up Cost Explorer / Compute Optimizer style
API costs are irrelevant here (this script doesn't call those), but a
full-account EC2/ECS/EKS/RDS sweep across every region is still many API
calls -- warn the user if they didn't ask for `--all-regions` explicitly
and the account looks large.

### Step 2 -- Read the raw JSON, not just the rendered report

The rendered report is a summary. When you need to reason precisely about
a specific resource (e.g. "does this VPC have a route to the internet from
the private subnet"), read the JSON directly -- it has the full boto3
response for every resource, including fields the report doesn't surface.

### Step 3 -- Build the requested viewpoint(s)

The report already includes a per-region Mermaid VPC topology diagram. If
the user asks for something the script doesn't generate automatically --
a compute/container topology diagram, a data-flow diagram between tiers,
a C4-style container diagram -- read `references/viewpoints.md` for the
mapping from AWS resource types to viewpoint elements, then hand-author the
additional Mermaid diagram(s) from the JSON inventory.

Hand-authored diagrams follow the same four rules the generated one does
(the `diagram-conventions.md` loaded above): every edge labelled with its real
connectivity (protocol and port for an application link, route table and
destination range for a routing one, direction via the arrowheads), no
unexplained abbreviation or unmeasurable adjective, one clause per label,
and a `subgraph Legend[...]` inventorying the symbols used. Reading
`vpc_topology_mermaid()` in `scripts/discover.py` is the fastest way to
match the house style -- it implements all four.

### Step 4 -- Summarize for the user

Call out, in plain language, anything structurally notable even though this
skill's job is discovery, not judgment (that's `aws-architecture-gap-analysis`):
VPCs with no NAT gateway, security groups open to 0.0.0.0/0, regions with
only a handful of resources (likely legacy/abandoned), S3 buckets without
default encryption.

## Output

- `reports/output/architecture-discovery.{md,html,pdf}`
- Optionally `reports/output/architecture-inventory.json` (recommended --
  pass `--json-out` every time so downstream skills and follow-up questions
  don't require re-querying AWS)

## Quality checks

1. Every region requested actually appears in the report (a region with
   zero resources should still show up with all-zero counts, not be
   silently dropped).
2. The Mermaid diagram block is valid (starts with `flowchart TB`, every
   node ID is a valid Mermaid identifier -- the script already sanitizes
   AWS IDs).
3. Every edge in every diagram, generated or hand-authored, carries a
   label describing the connection, and each diagram ends with a legend
   listing exactly the symbol kinds it used.
4. PDF output actually opens (`file reports/output/architecture-discovery.pdf`
   should say `PDF document`).
