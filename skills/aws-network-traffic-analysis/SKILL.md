---
name: aws-network-traffic-analysis
description: >
  Analyze VPC network traffic for anomalies and malicious activity: VPC
  Flow Logs via CloudWatch Logs Insights (top talkers, rejected traffic,
  protocol mix, external egress, a port-scan heuristic) plus GuardDuty
  network-related findings (Recon/UnauthorizedAccess/Trojan/Backdoor/
  CryptoCurrency), then render a Markdown/HTML/PDF report with traffic
  charts. Use this skill when someone asks to "analyze network traffic",
  "check VPC flow logs", "detect malicious traffic", "find anomalies in
  network traffic", "who is scanning our network", "check for data
  exfiltration", or "review incoming/outgoing traffic" for a VPC.
---

# AWS Network Traffic Analysis

Analyzes ingress/egress traffic for a VPC using CloudWatch Logs Insights
queries over VPC Flow Logs, layered with GuardDuty's own network-focused
detections. Read-only -- CloudWatch Logs `StartQuery` executes a query
against existing log data; it does not modify anything. See
`${CLAUDE_PLUGIN_ROOT}/PERMISSIONS.md` for the IAM policy.

## Before you start

1. **Confirm VPC Flow Logs are actually flowing to CloudWatch Logs.** This
   skill's Insights queries assume flow logs are delivered to a CloudWatch
   Logs log group in AWS's default record format. If the user isn't sure,
   or if a first run returns empty results across every query, load:

   ```
   view ${CLAUDE_PLUGIN_ROOT}/skills/aws-network-traffic-analysis/references/flow-logs-setup.md
   ```

   and help them enable flow logging before re-running the analysis --
   don't report "no anomalies found" when the real answer is "no flow
   logs exist to analyze."

2. Load the detection reference for what each canned query is actually
   looking for and AWS's own guidance on network threat detection:

   ```
   view ${CLAUDE_PLUGIN_ROOT}/skills/aws-network-traffic-analysis/references/detection-guide.md
   ```

3. Confirm with the user: profile/credentials, region, the CloudWatch Logs
   **log group name** flow logs are delivered to, and the lookback window
   (default 24 hours -- widen for a slower-moving investigation, narrow
   for "what's happening right now").

## Workflow

### Step 1 -- Run the collector

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/aws-network-traffic-analysis/scripts/traffic_analysis.py \
  --profile <profile> \
  --region us-east-1 \
  --log-group /vpc/flow-logs/vpc-0123abcd \
  --lookback-hours 24 \
  --json-out reports/output/traffic-evidence.json \
  --output-dir reports/output \
  --formats md,html,pdf
```

This produces: top talkers by bytes, protocol mix, rejected-traffic table,
a port-scan heuristic (sources touching an unusually high number of
distinct destination ports), top external (non-RFC1918) egress
destinations, and GuardDuty network-related findings.

### Step 2 -- Investigate before concluding "malicious"

A port-scan-heuristic hit or a large external-egress entry is a *lead*,
not a verdict. Before calling something malicious in the final report:

- Check whether the source/destination is a known, expected system
  (a legitimate vulnerability scanner, a monitoring agent, a CDN) --
  ask the user if the IP/CIDR isn't obviously internal or obviously
  public-internet-suspicious.
- Cross-reference a port-scan candidate or rejected-traffic spike against
  GuardDuty's own findings for the same source/timeframe -- if GuardDuty
  already flagged it, that corroborates the heuristic; if GuardDuty is
  silent, say the heuristic result is unconfirmed rather than asserting
  compromise.
- Large external egress isn't automatically exfiltration -- it can be a
  legitimate backup job, a CDN origin pull, or a data pipeline. Note the
  destination and volume, and ask rather than assume, unless the
  destination is corroborated by a GuardDuty `Trojan:`/`Backdoor:`/
  `CryptoCurrency:` finding.

### Step 3 -- Escalate real findings clearly

If GuardDuty independently confirms a `Trojan:`, `Backdoor:`, or
`CryptoCurrency:` finding tied to a resource also showing up in the flow
log anomalies, lead the report with that -- it's the strongest evidence of
actual compromise this skill can produce.

## Output

`reports/output/network-traffic-analysis.{md,html,pdf}`. Pairs with
`aws-security-review` (broader GuardDuty/Security Hub posture) and
`aws-architecture-discovery` (to confirm which subnet/resource an
IP address in the flow logs actually belongs to).

## Quality checks

1. If every query returned empty results, the report says so explicitly
   and points at `references/flow-logs-setup.md` rather than implying a
   clean bill of health.
2. Every "possible port scan" or "top external egress" entry is presented
   as a lead to investigate, with the corroborating (or non-corroborating)
   GuardDuty cross-reference stated -- never asserted as confirmed
   malicious without that corroboration.
3. IP addresses and ports in the findings are the actual values from the
   query results, not paraphrased or rounded.
