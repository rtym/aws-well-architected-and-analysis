# Enabling VPC Flow Logs to CloudWatch Logs

Source: AWS docs, `vpc/latest/userguide/flow-logs.html` and
`flow-log-records.html`.

This skill's collector (`shared.awslib.collectors.network_traffic`) assumes
flow logs are already being delivered to a CloudWatch Logs log group. If a
first run comes back empty across every query, check this before
concluding "no anomalies" -- there may be no log data at all.

## Quick check: does a flow log already exist?

```bash
aws ec2 describe-flow-logs --filter Name=resource-id,Values=<vpc-id> --profile <profile>
```

If this returns nothing, no flow log is capturing this VPC's traffic yet.

## Setting one up (CloudWatch Logs destination)

1. **Create (or choose) a CloudWatch Logs log group** to receive the
   records, e.g. `/vpc/flow-logs/<vpc-id>`.
2. **Create an IAM role** trusted by `vpc-flow-logs.amazonaws.com` with
   permission to create log streams and put log events into that log
   group (`logs:CreateLogGroup`, `logs:CreateLogStream`,
   `logs:PutLogEvents`, `logs:DescribeLogGroups`, `logs:DescribeLogStreams`).
3. **Create the flow log itself**, scoped to a VPC, a subnet, or an
   individual ENI, pointing at that log group and IAM role:

   ```bash
   aws ec2 create-flow-logs \
     --resource-type VPC \
     --resource-ids <vpc-id> \
     --traffic-type ALL \
     --log-destination-type cloud-watch-logs \
     --log-group-name /vpc/flow-logs/<vpc-id> \
     --deliver-logs-permission-arn <iam-role-arn> \
     --profile <profile>
   ```

CloudWatch Logs delivery has roughly a 5-minute latency from when traffic
occurs to when a record is queryable (S3 delivery is closer to 10 minutes)
-- don't expect a flow log enabled seconds ago to already have data for
`--lookback-hours 1`.

Enabling flow logs does not add latency or reduce throughput for the
actual network traffic -- capture happens out-of-band.

## Default vs. custom record format

**This skill's canned Insights queries assume the AWS default format**
(fixed field order, cannot be reordered or filtered at creation time):

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol
packets bytes start end action log-status
```

`action` is `ACCEPT`/`REJECT`; `log-status` is `OK`/`NODATA`/`SKIPDATA`
(the last two mean "no data was captured in this interval," not "no
traffic occurred" -- don't read `NODATA` as a clean signal).

## When to recommend a custom format instead

If the investigation needs to see the traffic **behind a NAT Gateway or an
EKS pod** (the default format only has the NAT'd/ENI-level address, not
the original client), or needs **TCP flag data** to distinguish a real
handshake from scan noise, recommend switching (or adding a second flow
log) to a **custom format** including:

- `pkt-srcaddr` / `pkt-dstaddr` -- the original packet-level source/
  destination, before NAT translation.
- `tcp-flags` -- bitmask (`FIN=1, SYN=2, RST=4, SYN-ACK=18`); a source
  sending many `SYN`-only (2) flows with no corresponding `SYN-ACK` is a
  classic scan signature.
- `flow-direction` -- `ingress`/`egress`, useful when a single ENI serves
  both directions and you want to split them cleanly.
- `traffic-path` -- numeric code for the egress path taken (e.g. `8` via
  Internet Gateway); helps confirm whether "external egress" really left
  the VPC to the public internet vs. through a VPC endpoint/peering path.
- `vpc-id`, `subnet-id`, `instance-id` -- when a single log group
  aggregates multiple VPCs/subnets and queries need to filter to one.

A useful custom format string covering all of the above:

```
${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${bytes} ${action}
${pkt-srcaddr} ${pkt-dstaddr} ${tcp-flags} ${flow-direction}
${traffic-path} ${vpc-id} ${subnet-id} ${instance-id}
```

If you switch to a custom format, the canned queries in
`shared/awslib/collectors/network_traffic.py` will still work (they only
reference fields present in the default format), but you can write
additional targeted queries against the new fields directly with
`network_traffic.run_insights_query()`.
