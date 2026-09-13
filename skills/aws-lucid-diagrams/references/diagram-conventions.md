# Diagram conventions (applies to every diagram this plugin produces)

Four rules. They hold for Lucid boards, for hand-authored Mermaid, and for
the Mermaid the `aws-architecture-discovery` script generates. A diagram
that breaks any of them is not finished.

## 1. Every relationship carries its connectivity detail

A bare line between two shapes says only "these are related," which the
reader already assumed. Label every connector with what actually crosses
it, drawn from the inventory -- not invented:

| Relationship | Label it with | Example |
|---|---|---|
| Subnet -> Internet Gateway | destination range, route table, direction | `0.0.0.0/0 via rtb-0a1: any protocol, inbound and outbound` |
| Subnet -> NAT Gateway | destination range, route table, direction | `0.0.0.0/0 via rtb-0b2: outbound only, replies allowed` |
| NAT Gateway -> Internet Gateway | translated source address | `egress translated to 52.1.2.3, replies only` |
| Compute -> database | protocol and port, plus TLS if known | `PostgreSQL, TCP 5432, TLS required` |
| Load balancer -> target | listener protocol/port -> target port | `HTTPS 443 to target group, HTTP 8080 to targets` |
| Compute -> VPC endpoint | protocol/port and that it stays private | `HTTPS 443 to Secrets Manager over a private address` |
| VPC <-> VPC peering | connection id, address ranges, transitivity | `pcx-9: private IPv4 between the two ranges, not transitive` |
| VPC -> Transit Gateway | attachment id, what it reaches | `attachment tgw-attach-7: private routing to other attached networks` |
| Anything -> Amazon S3 | protocol and path (internet vs. gateway endpoint) | `HTTPS 443 via gateway endpoint, never leaves AWS` |
| Event source -> AWS Lambda | invocation mode | `asynchronous invocation on object created` |

Direction is part of the detail: one arrowhead for one-way, two for
traffic both ways. If the inventory does not say what protocol is in use,
label what it does say (the route, the attachment, the permission) rather
than guessing a port.

## 2. Expand abbreviations, drop the buzzwords

Write the full term the first time it appears, with the short form after
it if the short form is what appears in AWS identifiers: **Virtual Private
Cloud (VPC)**, **NAT Gateway (Network Address Translation)**, **Availability
Zone**, **Elastic Load Balancer**, **Identity and Access Management (IAM)**.
The legend is the natural place for the ones that would clutter a node.

Cut words that describe nothing measurable: *scalable*, *robust*, *secure
by design*, *enterprise-grade*, *cloud-native*, *best-practice*,
*next-generation*, *seamless*, *highly available* (say `three Availability
Zones` instead). A label should state a fact from the inventory or not
exist.

## 3. Concise beats complete

- Node label: name/identifier on line one, the one or two facts that matter
  (address range, Availability Zone, engine, size) on line two. Nothing else.
- Edge label: one clause. `0.0.0.0/0 via rtb-0a1: outbound only` -- not a
  sentence about what NAT is.
- One diagram per viewpoint. Past roughly 25-30 shapes, split by viewpoint
  (network / compute / data) rather than shrinking the type.
- If a fact needs a paragraph, it belongs in the report text, not on the
  canvas.

## 4. Every diagram ends with a legend

The legend is an **inventory of what is on this canvas** -- only the symbol
kinds actually used, each with a count and one line saying what it means:

```
Legend -- symbols on this diagram
  Public internet x1 -- any address outside this account
  Virtual Private Cloud (VPC) x2 -- isolated private network; label shows its address range
  Subnet x3 -- address range in one Availability Zone;
               Public = route to the Internet Gateway, Private = out through a
               NAT Gateway, Isolated = no default route
  Gateway x3 -- Internet, NAT (Network Address Translation) or Transit Gateway;
                where packets leave a subnet
  VPC endpoint x2 -- private link to an AWS service; traffic stays on the AWS network
  Arrow = one connection. Label gives destination range, route table, protocol
          and direction. Two arrowheads = traffic flows both ways.
```

Rules for it:

- Only symbol kinds present on the diagram -- a legend entry with no shape
  behind it is noise.
- Include the count, so the legend doubles as the resource inventory.
- Explain the arrow notation too, not just the shapes.
- In Mermaid: a `subgraph Legend[...]` holding one node per kind, drawn in
  that kind's shape. In Lucid: a container placed bottom-left, holding one
  small instance of each icon used with its text beside it.

`vpc_topology_mermaid()` in
`skills/aws-architecture-discovery/scripts/discover.py` implements all four
rules for the generated network diagram -- read it before hand-authoring a
diagram in the same report, so the two match.
