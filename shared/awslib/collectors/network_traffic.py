"""VPC Flow Log analysis (via CloudWatch Logs Insights) and GuardDuty network
findings. Assumes flow logs are delivered to a CloudWatch Logs log group in
the default record format (see AWS docs: version, account-id, interface-id,
srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end,
action, log-status). S3-delivered flow logs are out of scope for the
Insights queries here -- point the skill's Athena reference at those instead.
"""
from __future__ import annotations

import time

from ..session import AwsContext, ignore_access_denied
from .security import guardduty_findings

NETWORK_FINDING_TYPE_PREFIXES = (
    "Recon:",
    "UnauthorizedAccess:",
    "Trojan:",
    "Backdoor:",
    "CryptoCurrency:",
    "Impact:",
    "Behavior:",
)

# Canned CloudWatch Logs Insights queries against the default VPC Flow Logs
# record format ingested with the standard `message` field layout.
QUERIES = {
    "top_talkers_by_bytes": """
        fields srcAddr, dstAddr, bytes
        | stats sum(bytes) as totalBytes by srcAddr, dstAddr
        | sort totalBytes desc
        | limit 25
    """,
    "rejected_traffic": """
        filter action = "REJECT"
        | stats count(*) as rejects by srcAddr, dstAddr, dstPort
        | sort rejects desc
        | limit 50
    """,
    "distinct_dst_ports_per_src": """
        stats count_distinct(dstPort) as distinctPorts by srcAddr
        | sort distinctPorts desc
        | limit 25
    """,
    "top_external_egress": """
        filter dstAddr not like /^10\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^192\\.168\\./
        | stats sum(bytes) as totalBytes by srcAddr, dstAddr
        | sort totalBytes desc
        | limit 25
    """,
    "traffic_by_protocol": """
        stats sum(bytes) as totalBytes, count(*) as flows by protocol
        | sort totalBytes desc
    """,
}

PORT_SCAN_DISTINCT_PORT_THRESHOLD = 15


@ignore_access_denied(default=list)
def run_insights_query(
    ctx: AwsContext, region: str, log_group: str, query: str, start_time: int, end_time: int, timeout_s: int = 60
) -> list[dict]:
    logs = ctx.client("logs", region=region)
    query_id = logs.start_query(
        logGroupName=log_group, startTime=start_time, endTime=end_time, queryString=query
    )["queryId"]
    waited = 0
    while waited < timeout_s:
        resp = logs.get_query_results(queryId=query_id)
        if resp["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(2)
        waited += 2
    rows = []
    for result in resp.get("results", []):
        rows.append({field["field"]: field["value"] for field in result})
    return rows


def analyze_flow_logs(
    ctx: AwsContext, region: str, log_group: str, start_time: int, end_time: int
) -> dict:
    """Run every canned query and layer a port-scan heuristic on top."""
    results = {
        name: run_insights_query(ctx, region, log_group, query, start_time, end_time)
        for name, query in QUERIES.items()
    }
    scan_candidates = [
        row
        for row in results.get("distinct_dst_ports_per_src", [])
        if _as_int(row.get("distinctPorts")) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD
    ]
    results["port_scan_candidates"] = scan_candidates
    return results


def network_findings(ctx: AwsContext, region: str) -> list[dict]:
    findings = guardduty_findings(ctx, region, max_findings=500)
    return [f for f in findings if f.get("Type", "").startswith(NETWORK_FINDING_TYPE_PREFIXES)]


def _as_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
