"""VPC Flow Log analysis (via CloudWatch Logs Insights) and GuardDuty network
findings. Assumes flow logs are delivered to a CloudWatch Logs log group in
the default record format (see AWS docs: version, account-id, interface-id,
srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end,
action, log-status). S3-delivered flow logs are out of scope for the
Insights queries here -- point the skill's Athena reference at those instead.
"""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

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


def run_insights_query(
    ctx: AwsContext, region: str, log_group: str, query: str, start_time: int, end_time: int, timeout_s: int = 60
) -> list[dict]:
    """The rows of one Logs Insights query; see `query_with_status` for
    whether the query finished."""
    return query_with_status(ctx, region, log_group, query, start_time, end_time, timeout_s)[0]


@ignore_access_denied(default=lambda: ([], "Denied"))
def query_with_status(
    ctx: AwsContext, region: str, log_group: str, query: str, start_time: int, end_time: int, timeout_s: int = 60
) -> tuple[list[dict], str]:
    """(rows, final status). The status matters: a query still Running
    when the local timeout ends, or one that Failed or timed out on the
    service side, returns few or no rows, which reads as "no such traffic"
    unless the report can say the query never finished."""
    logs = ctx.client("logs", region=region)
    query_id = logs.start_query(
        logGroupName=log_group, startTime=start_time, endTime=end_time, queryString=query
    )["queryId"]
    waited = 0
    while waited < timeout_s:
        resp = logs.get_query_results(queryId=query_id)
        # Every terminal state; missing "Timeout" made a timed-out query
        # spin for the full local timeout before returning nothing.
        if resp["status"] in ("Complete", "Failed", "Cancelled", "Timeout", "Unknown"):
            break
        time.sleep(2)
        waited += 2
    if resp["status"] in ("Scheduled", "Running"):
        _stop_query(logs, query_id)
    rows = []
    for result in resp.get("results", []):
        rows.append({field["field"]: field["value"] for field in result})
    return rows, resp["status"]


def _stop_query(logs, query_id: str) -> None:
    """Stop a query the local timeout gave up on: left running, it keeps
    scanning (and billing) and holds one of the account's concurrent
    Logs Insights query slots. Best effort; the rows are already read."""
    try:
        logs.stop_query(queryId=query_id)
    except ClientError:
        pass


def analyze_flow_logs(
    ctx: AwsContext, region: str, log_group: str, start_time: int, end_time: int
) -> dict:
    """Run every canned query and layer a port-scan heuristic on top."""
    results = {}
    incomplete = []
    statuses = {}
    for name, query in QUERIES.items():
        rows, status = query_with_status(ctx, region, log_group, query, start_time, end_time)
        results[name] = rows
        statuses[name] = status
        # A denied query is listed under Access Gaps instead.
        if status not in ("Complete", "Denied"):
            incomplete.append({"Query": name, "Status": status})
    scan_candidates = [
        row
        for row in results.get("distinct_dst_ports_per_src", [])
        if _as_int(row.get("distinctPorts")) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD
    ]
    results["port_scan_candidates"] = scan_candidates
    results["incomplete_queries"] = incomplete
    # Every query's final status, so the report can tell "no such traffic"
    # from a query that was denied or never finished.
    results["query_status"] = statuses
    return results


def network_findings(ctx: AwsContext, region: str) -> list[dict]:
    findings = guardduty_findings(ctx, region, max_findings=500)
    return [f for f in findings if f.get("Type", "").startswith(NETWORK_FINDING_TYPE_PREFIXES)]


def _as_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
