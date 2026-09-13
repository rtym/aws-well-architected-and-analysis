# AWS icon mapping and crossing-minimization layout rules

## Where the shapes actually live

Lucid's current AWS icon set is named **"AWS 2024"**. Browse it via
`ReadMcpResourceTool` (server `"claude.ai Lucid"`) against these URIs --
no `document_id` needed, unlike the `lucid_shape_library` tool:

- `lucid://shape-libraries/aws-2024/common` -- ~36 most-used shapes.
- `lucid://shape-libraries/aws-2024/{category}` -- full catalogue by
  category (`compute`, `database`, `storage`, `containers`,
  `networking-and-content-delivery`, `security-identity-and-compliance`,
  `serverless`, `general-resources`, etc.), ~844 shapes total.
- `lucid://shape-libraries/aws-2024/group-shapes` -- **containers**:
  `AWSAccountAWS2024`, `RegionAWS2024`, `AvailabilityZoneAWS2024`,
  `VirtualPrivateCloudVPCAWS2024`, `PublicSubnetAWS2024`,
  `PrivateSubnetAWS2024`, `AutoScalingGroupAWS2024`, `SecurityGroupAWS2024`.

Each entry has an `id` (the `className` to pass to `namedShape`/
`namedContainer`), a human-readable `label`, and a `defaultFillColor`.
`general-resources` also has the plain **Internet** icon
(`ResInternet48LightAWS2024`) for a non-AWS-service traffic source.

## Resource type -> AWS icon category

The `aws-architecture-discovery` JSON inventory's top-level keys map to
AWS Architecture Icons categories as follows -- look up the concrete
`className` in the matching category resource above.

| Inventory field | AWS icon category | Specific icon to search for |
|---|---|---|
| `Vpcs` | Networking & Content Delivery | "Virtual private cloud" / VPC container |
| `Subnets` | Networking & Content Delivery | "VPC subnet" (public/private variants if the library has them) |
| `InternetGateways` | Networking & Content Delivery | "Internet gateway" |
| `NatGateways` | Networking & Content Delivery | "NAT gateway" |
| `VpcEndpoints` | Networking & Content Delivery | "VPC endpoints" |
| `TransitGatewayAttachments` | Networking & Content Delivery | "Transit gateway" |
| `Instances` | Compute | "Amazon EC2" instance icon |
| `AutoScalingGroups` | Compute | "Amazon EC2 Auto Scaling" |
| `LoadBalancersV2` | Networking & Content Delivery | "Elastic Load Balancing" (ALB/NLB variant per `Type`) |
| `EcsClusters` | Containers | "Amazon ECS" |
| `EksClusters` | Containers | "Amazon EKS" |
| `RdsInstances` / `RdsClusters` | Database | "Amazon RDS" (engine-specific icon if available -- match `Engine` field) |
| `DynamoDbTables` | Database | "Amazon DynamoDB" |
| `ElastiCacheClusters` | Database | "Amazon ElastiCache" |
| `LambdaFunctions` | Compute | "AWS Lambda" |
| `S3Buckets` | Storage | "Amazon S3" (bucket icon) |

If the Lucid AWS shape library has both "service" icons (colored squares,
used inside architecture diagrams) and "resource" icons (used for detailed
resource-level diagrams), prefer **service icons** for an
account/system-level architecture diagram and **resource icons** only when
the user explicitly wants a very detailed, single-service deep-dive.

## Standard Import JSON: containment and sizing numbers

These come from `lucid://skills/diagram-specification` (read the full
resource before authoring JSON -- this is a condensed cheat-sheet, not a
replacement). `lucid_validate_diagram_specification` enforces all of it.

- **Containment is strict:** a child shape's *entire* bounding box must
  fit inside its container's bounding box -- a shape whose box crosses the
  container edge is not contained, and assisted layout will not pull it
  back in.
- **Padding:** after placing a container's children, the container should
  have at least **80px of clearance** on every side between the children's
  combined bounding box and the container's own edge. (A verified working
  example from this session: a 120x120 icon centered in a 300x300
  container -- i.e. 90px padding on every side -- validated clean and
  rendered legibly.)
- **Collision clearance:** any two non-container shapes need at least
  **60px** of horizontal or vertical separation.
- **Nested containers should NOT use assisted layout** (`"assistedLayout":
  false` on any container that itself holds other containers, e.g. an
  Account container holding a Region container holding AZ containers) --
  assisted layout re-arranging one level can undo careful positioning at
  another. A container holding only leaf shapes (icons) can safely use
  `"assistedLayout": true`.
- **Text sizing:** a shape's text auto-scales to fit its box in both
  directions -- there's no minimum font size floor, so an undersized box
  shows up as *smaller type than its neighbors*, not as clipped/overflowing
  text. Keep boxes of the same visual role (e.g. every service icon) the
  same size so their labels read consistently.

## Editing an existing document: the endpoint-style gotcha

`lucid_add_line` and `lucid_edit_item` (used to modify a diagram already
created -- see SKILL.md Step 0) take a **different, capitalized** enum for
line endpoint styles than the Standard Import JSON format used to *create*
a diagram:

| Standard Import JSON (`lucid_create_diagram_from_specification`) | Live edit tools (`lucid_add_line` / `lucid_edit_item`) |
|---|---|
| `"none"` | `"None"` |
| `"arrow"` | `"Arrow"` |
| `"hollowArrow"` | `"Hollow Arrow"` |
| `"openArrow"` | `"Open Arrow"` |

(The live-edit enum is longer and covers UML/BPMN/ERD styles too --
`lucid_add_line`'s own validation error lists the full set if you pass an
invalid value.) Passing a lowercase JSON-style value to `lucid_add_line`
fails with a validation error naming the allowed values -- if you see
that, this mismatch is almost certainly why.

## Labelled connectors and the legend container

The content rules live in `diagram-conventions.md`; this is how to satisfy
them in Lucid specifically.

**Connector labels.** Every line needs text on it (route + protocol +
direction). The label goes in the line's own text field -- check the exact
field name in `lucid://skills/diagram-specification` for Standard Import
JSON, and in the tool schema for `lucid_add_line`/`lucid_edit_item` when
editing a live document; the two formats differ here the same way their
endpoint-style enums do. Practical constraints:

- Keep the label to one clause (~40 characters). Lucid centres it on the
  line, so a long label overlaps whatever the line passes near.
- Leave at least **80px** of clear space along the segment the label sits
  on -- treat a labelled connector as needing roughly the same clearance as
  a small shape.
- Set the arrowheads to match reality: one endpoint `"Arrow"` for one-way
  traffic, both endpoints `"Arrow"` for bidirectional (`"arrow"` lowercase
  in Standard Import JSON -- see the enum table above).

**Legend container.** Place a plain container (not an AWS group shape) in
the bottom-left of the canvas, outside every Region/VPC container, holding:

- one instance of each icon actually used on the board, at roughly half the
  size of the real ones, each with its count and one-line meaning as text
  beside it;
- one text block explaining the arrow notation.

Lay it out as a single column with ~40px between rows, size the container
so its children clear the edges by the usual 80px, and set
`"assistedLayout": false` on it so the paired icon/text rows don't get
re-flowed. Build it last, once you know which icons the board actually
contains -- a legend listing an icon that isn't on the canvas is a defect
the visual re-check should catch.

## Crossing-minimization layout rules

Applied roughly in this order -- each rule alone removes a class of
avoidable crossings:

1. **Containers first.** Draw the VPC container, then subnet containers
   nested inside it, before placing any service icon. Everything a subnet
   contains should be positioned inside that subnet's container bounds.
2. **Edge-to-center flow.** Internet-facing elements (Internet Gateway,
   public Load Balancer) go at the *outer* edge of the VPC container.
   Compute goes in the middle layer. Data stores go at the *innermost*
   layer, closest to whichever compute actually calls them. This mirrors
   real traffic flow and means most connectors naturally run in one
   direction without needing to cross back over already-drawn elements.
3. **Group by relationship, not by resource type.** Don't lay out "all EC2
   instances in a row, then all RDS instances in a row" if instance A only
   talks to database A and instance B only talks to database B -- place A
   near database A and B near database B, even though that interleaves
   resource types. Grouping by *who talks to whom* minimizes crossings far
   more than grouping by service type.
4. **One connector per real relationship, routed orthogonally.** Avoid
   diagonal lines cutting across unrelated shapes; prefer right-angle
   routing that hugs container boundaries.
5. **Split by viewpoint before you split by "it's getting crowded."** If
   network, compute, and data elements together exceed ~25-30 shapes,
   produce separate network/compute/data diagrams (see
   `aws-architecture-discovery`'s viewpoints reference) rather than one
   dense diagram -- this is a layout decision, not a last resort.

## What the visual re-check pass is actually looking for

When you Read the exported PNG, you are specifically checking for the
failure modes crossing-minimization rules don't fully prevent by
construction:

- A label longer than its shape's width, spilling into a neighboring shape.
- A connector with no label at all, or a connector label overlapping a
  line, a shape, or another label.
- A legend that is missing, clipped, or out of step with the icons actually
  drawn (an entry with no shape behind it, or a shape kind with no entry).
- Two connectors that cross more than once between the same pair of
  groups (usually fixable by swapping the vertical order of two sibling
  shapes).
- An icon rendered at a size where its service identity isn't recognizable
  (compare against how it looks in the shape library search results).
- Any shape or label clipped by the canvas/page boundary.
