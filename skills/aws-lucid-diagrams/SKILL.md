---
name: aws-lucid-diagrams
description: >
  Draw professional AWS architecture diagrams directly in Lucidchart via
  the Lucid MCP connector, using the current official AWS Architecture
  Icons shape library (not generic boxes), laid out to minimize edge
  crossings and overlap -- then visually re-check the exported diagram
  (Claude's own vision on the exported image, i.e. an OCR/legibility pass)
  and re-layout if labels overlap, edges cross excessively, or icons are
  illegible, before handing the board back to the user. Use this skill
  when someone asks to "draw this in Lucid", "create a Lucidchart
  diagram", "make a Lucid architecture diagram", "visualize the AWS
  architecture in Lucid", or wants a polished, shareable diagram (as
  opposed to a Mermaid code block) of AWS infrastructure. Typically
  consumes the JSON inventory produced by `aws-architecture-discovery`.
---

# AWS Lucid Diagrams

Turns an AWS infrastructure inventory (ideally the JSON from
`aws-architecture-discovery`, but a free-form description works too) into
a polished, professional diagram in Lucidchart, using AWS's own
architecture icon set, via the Lucid MCP connector -- then checks its own
work visually before calling the diagram done.

This skill produces a *live, editable Lucid document* the user can keep
iterating on by hand, which is a different deliverable from the Mermaid
diagrams `aws-architecture-discovery` embeds in its Markdown report --
reach for this skill specifically when the user wants something they can
open in Lucidchart, present, or hand to a non-technical stakeholder.

## Before you start

### 1. Confirm Lucid MCP is authenticated

The full Lucid tool set (board/document creation, shape placement,
shape-library search, export -- names like `lucid_create_diagram_from_specification`,
`lucid_shape_library`, `lucid_export_document_as_PNG`) only appears after
the user has connected Lucid. Always `ToolSearch("Lucid")` first to see
what's actually callable this session -- never guess at tool names or
assume the connector is already authenticated.

If that search returns only `mcp__claude_ai_Lucid__authenticate` and
`..._complete_authentication` (or nothing at all), Lucid isn't connected
yet. **This is a user-side action you cannot complete for them** -- calling
`authenticate` does not hand back an authorization URL to relay; it
returns an instruction to run the client's own connector UI. Tell the
user directly:

1. Run `/mcp` in Claude Code and look for **"claude.ai Lucid"** in the
   list.
2. **If it isn't listed at all**, the connector first needs enabling on
   the claude.ai side -- have them go to claude.ai's connector/integration
   settings, find "Lucid," and enable it there. Then come back and run
   `/mcp` again.
3. Selecting "claude.ai Lucid" in `/mcp` runs the OAuth flow in their
   browser. Once it reports success, `ToolSearch("Lucid")` will show the
   real tool surface, and `authenticate`/`complete_authentication` will no
   longer appear (they're replaced, not layered on top).

Don't loop on calling `authenticate` yourself expecting a URL to appear --
its response only ever points back at `/mcp`. Wait for the user to
confirm before re-running `ToolSearch("Lucid")`.

### 2. Load the icon/layout reference and the diagram conventions

```
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-lucid-diagrams/references/icon-and-layout-guide.md
view ${CLAUDE_PLUGIN_ROOT}/skills/aws-lucid-diagrams/references/diagram-conventions.md
```

The first has the resource-type -> AWS icon-category mapping, the concrete
Lucid shape-library resource URIs, the container-padding/containment
numbers, the endpoint-style gotcha, and the crossing-minimization layout
rules -- read it before placing shapes, not after.

The second is the four content rules every diagram in this plugin follows,
and they are not optional here: **every connector carries its connectivity
detail** (route, protocol/port, direction), **abbreviations are expanded**
and buzzwords cut, **labels stay to one clause**, and **the board carries a
legend** inventorying the icons used and what each means.

### 3. If you'll be hand-authoring Standard Import JSON, read the spec resource first

Only applies when you're about to call `lucid_create_diagram_from_specification`
(first-time creation of a diagram -- see Step 0 below for the "editing an
existing document" case, which doesn't need this). That tool's own
description makes reading `lucid://skills/diagram-specification` (via
`ReadMcpResourceTool`, server `"claude.ai Lucid"`) a **hard gate** --
do it before authoring any JSON, not after a failed attempt. It defines
the shape/container/line schema, containment rules, and text-fit sizing
math the reference doc's numbers are derived from.

### 4. Get the inventory

If the user hasn't already run `aws-architecture-discovery` and doesn't
have a JSON inventory to point at, offer to run it first:

```
${CLAUDE_PLUGIN_ROOT}/bin/run-skill-script ${CLAUDE_PLUGIN_ROOT}/skills/aws-architecture-discovery/scripts/discover.py --profile <profile> --region <region> --json-out /tmp/inventory.json
```

`run-skill-script` runs the script in the plugin's own Python virtualenv. On
first use it creates that virtualenv and installs `requirements.txt` (about a
minute; progress goes to stderr). If it exits saying Python 3.11+ is missing,
relay its install hint to the user rather than retrying. If only PDF export
fails (WeasyPrint needs Pango: `brew install pango` on macOS), the Markdown
and HTML reports are already written -- rerun with `--formats md,html` or
tell the user how to enable PDF.

A free-form description of the architecture also works if the user just
wants a conceptual diagram rather than an as-built one -- don't insist on
a live AWS pull when the user is describing a target/future-state design.

## Workflow

### Step 0 -- Decide: new diagram, or editing one that already exists?

These use entirely different tools -- pick the right path before doing
anything else:

- **Brand-new diagram:** `lucid_create_diagram_from_specification` (hand-
  author Standard Import JSON -- Steps 1-4 below). This tool *only ever
  creates a new document*; it cannot update one that already exists, so
  never call it again against an existing diagram just to add something.
- **Adding to / changing a diagram already created (in this conversation or
  a past one):** call `fetch` (or `lucid_search_document`) with the
  document's ID first to get the real item IDs of what's already on the
  page, then use `lucid_add_block` (new shapes), `lucid_edit_item`
  (resize/reposition/retext/re-route an existing block or line),
  `lucid_add_line` (new connectors), and `lucid_delete_items` as needed.
  Re-export and visually re-check (Step 4) after edits the same as after a
  fresh creation.

The rest of this section (Steps 1-3) covers authoring the JSON for a
brand-new diagram; if you're editing an existing one, skip to Step 4 once
your `lucid_add_block`/`lucid_edit_item`/`lucid_add_line` calls are done.

### Step 1 -- Find the AWS icon shape library, don't default to generic shapes

The current library is concretely named **"AWS 2024"** in Lucid's resource
system, not something you need to search for by guessing a name:

- `lucid://shape-libraries/aws-2024/common` -- the ~36 most-used shapes;
  check here first.
- `lucid://shape-libraries/aws-2024/{category}` for the full catalogue
  (~844 shapes) by category -- e.g. `compute`, `database`,
  `networking-and-content-delivery`, `storage`, `containers`,
  `security-identity-and-compliance`, `general-resources` (for the plain
  Internet/user/globe icons that aren't a specific AWS service).
- `lucid://shape-libraries/aws-2024/group-shapes` -- the **container**
  shapes: `AWSAccountAWS2024`, `RegionAWS2024`, `AvailabilityZoneAWS2024`,
  `VirtualPrivateCloudVPCAWS2024`, `PublicSubnetAWS2024`,
  `PrivateSubnetAWS2024`, `AutoScalingGroupAWS2024`, `SecurityGroupAWS2024`,
  among others.

Read these via `ReadMcpResourceTool` (server `"claude.ai Lucid"`) --
they don't require a `document_id`, unlike the `lucid_shape_library` tool
(which only works against shapes already-insertable into a specific
existing document). Every AWS resource on the diagram must use its actual
AWS service/container icon (`namedShape`/`namedContainer` with the right
`className`) -- generic rectangles/clouds are not acceptable for a "modern
icons" AWS diagram.

### Step 2 -- Group before you place

Following `references/icon-and-layout-guide.md`:

1. VPC and subnet boundaries become **container shapes** (Lucid group/
   container elements) that everything else nests inside.
2. Within each subnet, group compute resources that talk to the same
   downstream data store or load balancer near each other.
3. Place load balancers and gateways (IGW/NAT/Transit Gateway) at the
   boundary between tiers (edge of the VPC, edge of a subnet), matching
   how traffic actually flows -- this alone removes most avoidable
   crossings before you've drawn a single connector.

### Step 3 -- Connect, validate, then create

Draw connectors only for real relationships in the inventory (route table
targets, target-group membership, RDS connectivity, VPC peering/Transit
Gateway attachments) -- don't connect everything to everything. Manually
position nodes so connector lines route orthogonally around containers
rather than through them (see the layout rules in the reference doc).

**Give every connector a text label** stating what crosses it -- destination
range and route table for a routing relationship, protocol and port for an
application one, and an arrowhead on each end that actually carries traffic
(`0.0.0.0/0 via rtb-0a1: outbound only, replies allowed`; `PostgreSQL, TCP
5432, TLS required`). Take the values from the inventory; where it doesn't
record a port, label the relationship it does record rather than inventing
one. Keep each label to a single clause, and expand abbreviations in the
node/icon labels (`NAT Gateway (Network Address Translation)`).

**Then add the legend container**, bottom-left of the canvas: one small
instance of each icon actually used, with its count and a one-line meaning
beside it, plus a line explaining the arrow notation. See rule 4 in
`references/diagram-conventions.md` for the exact shape of it. A board
without a legend is not done.

Before calling `lucid_create_diagram_from_specification`, run your JSON
through `lucid_validate_diagram_specification` -- it catches both
structural mistakes (which would otherwise fail the import outright with
an unhelpful bare 400) and layout mistakes (collisions, containment
violations, connector paths crossing unrelated shapes) while it's still
free to fix. Iterate until it comes back clean, then create the document.

If you're instead editing an existing document (Step 0's second path),
`lucid_add_line`/`lucid_edit_item` use a **different, capitalized**
endpoint-style enum (`"None"`, `"Arrow"`, `"Hollow Arrow"`, ...) than the
Standard Import JSON format's lowercase values (`"none"`, `"arrow"`) --
copying a style string from JSON you wrote earlier into one of these live
edit calls will fail validation. See the reference doc for the mapping.

### Step 4 -- Export and visually re-check (the OCR pass)

Export the board as an image (PNG) using the Lucid MCP's export
capability, then **Read the exported image file** -- Claude's native
vision on the image *is* the OCR/legibility check here, and is more
reliable than a plain text-extraction OCR tool for judging layout quality.
Look specifically for:

- Overlapping or truncated labels (text spilling out of its shape or
  behind another shape), including connector labels sitting on top of a
  line or each other.
- Any connector with no label, or a label too small to read at normal zoom.
- A legend that is missing, clipped, or lists an icon the diagram doesn't
  actually use.
- Icons rendered too small to identify at a normal zoom level.
- Connector lines crossing through unrelated shapes, or crossing each
  other more than necessary between two groups.
- Any element clipped at the canvas edge.

If you find any of these, adjust positions/spacing in Lucid and export
again. Cap this at **3 iterations** -- if it's still messy after three
passes, say so explicitly to the user rather than silently shipping a
cluttered diagram, and suggest splitting it into multiple diagrams (e.g.
one per VPC, or network vs. compute vs. data viewpoints) instead of
cramming everything onto one canvas.

### Step 5 -- Hand back the result

Give the user the Lucid document link/ID and mention which viewpoint(s)
it covers. If they also want a static copy, export a final PNG/PDF
alongside it.

## Output

A Lucid document (link/ID from the MCP tool) using real AWS architecture
icons, organized by network/compute/data grouping, every connector labelled
with its connectivity detail, a legend inventorying the icons used, and
verified visually for legibility -- plus an optional exported PNG/PDF.

## Quality checks

1. Every AWS resource shape is the actual AWS service icon, not a generic
   box, arrow, or cloud shape.
2. VPC/subnet boundaries are represented as containers, not just labeled
   rectangles floating disconnected from their contents.
3. Every connector has a label naming the route, protocol/port or
   attachment it represents, and arrowheads that match the real direction
   of traffic.
4. The board has a legend covering exactly the icon kinds on the canvas,
   each with a count and a plain-language meaning, plus the arrow notation.
5. No unexplained abbreviation and no unmeasurable adjective ("scalable",
   "highly available") appears anywhere on the canvas.
6. You performed at least one visual re-check pass (Step 4) before
   declaring the diagram done, and can state what you looked for.
7. If a viewpoint has more than ~25-30 resources, it was split into
   multiple diagrams rather than left as one illegible canvas.
8. For a brand-new diagram, `lucid_validate_diagram_specification` was run
   and came back clean before `lucid_create_diagram_from_specification`
   was called. For an edit to an existing diagram, `fetch` was used to get
   real item IDs before any `lucid_edit_item`/`lucid_add_line` call
   referencing them.
