---
name: aws-architecture-gap-analysis
description: >
  Synthesize architecture inventory, Well-Architected pillar evidence, and
  security findings into a single gap analysis: what's structurally
  missing or risky in the current AWS architecture, which security issues
  matter most in an architectural context (not just a raw finding count),
  and prioritized recommendations with an effort/impact estimate -- then
  render a Markdown/HTML/PDF gap-analysis report. Use this skill when
  someone asks for a "gap analysis", "architecture assessment",
  "architecture review findings", "what's wrong with our architecture",
  "prioritize our AWS risks", or "combine the security and architecture
  findings into one report". This is a synthesis skill with no AWS API
  calls of its own -- it reads the outputs of `aws-architecture-discovery`,
  `aws-well-architected-review`, and `aws-security-review`.
---

# AWS Architecture Gap Analysis

Synthesizes evidence collected by the other AWS skills into one
prioritized gap analysis. This skill has no `scripts/` of its own and
makes no AWS API calls -- it is pure reasoning over already-collected
JSON/reports, which is exactly why it must cite its sources precisely
rather than re-asserting facts from memory.

## Before you start

1. Load the synthesis framework:

   ```
   view ${CLAUDE_PLUGIN_ROOT}/skills/aws-architecture-gap-analysis/references/gap-analysis-framework.md
   ```

2. Confirm you have (or can get) the inputs. Ask the user, or run the
   upstream skills yourself if they're missing and the user is fine with a
   live AWS pull:

   - `aws-architecture-discovery`'s JSON inventory (`--json-out`) --
     required. Without it there is no factual basis for an architecture
     gap analysis.
   - `aws-well-architected-review`'s evidence pack and any findings you or
     the user already scored -- strongly recommended; if absent, offer to
     run at least the pillars most relevant to what the user is worried
     about.
   - `aws-security-review`'s evidence/report -- strongly recommended for
     the security-issue half of the analysis.
   - `aws-cost-optimization`'s report -- optional, only if the user wants
     cost folded into the same prioritization.

   If a required input is missing, say so and offer to generate it rather
   than filling the gap with assumptions.

## Workflow

### Step 1 -- Cross-reference, don't just concatenate

For every architectural gap you identify, check whether it's already
present as a Well-Architected finding or a security finding, and merge
them into one entry instead of reporting the same issue three times under
three headings (e.g. "single NAT Gateway" appears in both the discovery
report and Reliability pillar REL11 -- one gap entry, citing both
sources).

### Step 2 -- Classify each gap

Using `references/gap-analysis-framework.md`'s categories: **Architectural
gap** (a structural weakness -- missing redundancy, no fault isolation, a
data store reachable directly from the internet-facing tier), **Security
issue** (a control gap or active finding), or **Both** (most single-AZ,
wide-open-security-group, and unencrypted-data-store findings are both).

### Step 3 -- Prioritize by blast radius x likelihood, not by finding count

A single HIGH-risk architectural gap affecting the production data tier
outranks twenty low-severity Security Hub findings on a dev account. State
your prioritization logic in the report, not just a sorted list.

### Step 4 -- Recommend with effort/impact, and sequence dependencies

Every recommendation gets a rough effort estimate (quick config change /
requires a change window / requires a redesign) and impact (which pillar
and which specific risk it retires). Sequence recommendations that depend
on each other (e.g. "enable Security Hub" before "action Security Hub
findings").

## Output

`reports/output/architecture-gap-analysis.{md,html,pdf}`, built with
`shared.reporting.report.Report` (see any other skill's `scripts/*.py` for
the pattern) -- typically: an executive summary, a prioritized gap table
(Gap / Category / Pillar(s) / Severity / Sources cited / Recommendation /
Effort), and a short section per top-priority gap with full detail.

## Quality checks

1. Every gap cites which upstream report/JSON field it came from -- no gap
   appears without a traceable source.
2. No gap is reported more than once under different names -- cross-check
   before finalizing.
3. The prioritization order is explained, not just presented.
4. If an upstream input was missing or stale, the report says so in the
   executive summary rather than presenting partial coverage as complete.
