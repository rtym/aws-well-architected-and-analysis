#!/usr/bin/env python3
"""Analyze VPC network traffic for a region: CloudWatch Logs Insights over
VPC Flow Logs (top talkers, rejected traffic, external egress, protocol
mix, port-scan heuristic) plus GuardDuty network-related findings
(Recon/UnauthorizedAccess/Trojan/Backdoor/etc.) -- then render a
Markdown/HTML/PDF report with traffic charts.

Read-only. Requires VPC Flow Logs already delivered to a CloudWatch Logs
log group (see references/flow-logs-setup.md if none exists yet).
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from shared.awslib.cli import base_parser, formats_tuple, make_context  # noqa: E402
from shared.awslib.collectors import network_traffic as nt  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Analyze VPC Flow Logs and GuardDuty network findings for anomalies and malicious traffic.")
    parser.add_argument("--log-group", required=True, help="CloudWatch Logs log group VPC Flow Logs are delivered to")
    parser.add_argument("--lookback-hours", type=int, default=24, help="Lookback window in hours (default: 24)")
    return parser.parse_args(argv)


def collect(ctx, region: str, log_group: str, lookback_hours: int) -> dict:
    end = datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(hours=lookback_hours)
    start_epoch, end_epoch = int(start.timestamp()), int(end.timestamp())
    return {
        "Window": {"Start": start.isoformat(), "End": end.isoformat()},
        "FlowLogAnalysis": nt.analyze_flow_logs(ctx, region, log_group, start_epoch, end_epoch),
        "NetworkFindings": nt.network_findings(ctx, region),
    }


def build_report(data: dict, region: str, log_group: str) -> Report:
    report = Report(
        title="AWS VPC Network Traffic Analysis",
        subtitle=f"Region {region} -- log group {log_group}",
        meta={"Window": f"{data['Window']['Start']} to {data['Window']['End']}"},
    )

    flow = data["FlowLogAnalysis"]

    top_talkers = flow.get("top_talkers_by_bytes", [])
    if top_talkers:
        labels = [f"{r['srcAddr']}→{r['dstAddr']}" for r in top_talkers[:10]]
        values = [float(r.get("totalBytes", 0)) for r in top_talkers[:10]]
        chart_uri = charts.bar_chart(labels, values, title="Top talkers by bytes transferred", ylabel="Bytes", horizontal=True)
        report.add_section("Top Talkers", f"![Top talkers]({chart_uri})")
    else:
        report.add_section("Top Talkers", "No flow log records in this window.")

    protocol_mix = flow.get("traffic_by_protocol", [])
    if protocol_mix:
        labels = [r.get("protocol", "?") for r in protocol_mix]
        values = [float(r.get("totalBytes", 0)) for r in protocol_mix]
        chart_uri = charts.pie_chart(labels, values, title="Traffic volume by protocol")
        report.add_section("Protocol Mix", f"![Protocol mix]({chart_uri})")
    else:
        report.add_section("Protocol Mix", "No flow log records in this window.")

    rejected = flow.get("rejected_traffic", [])
    if rejected:
        rows = [
            {"Source": r.get("srcAddr"), "Destination": r.get("dstAddr"), "Port": r.get("dstPort"), "Rejects": r.get("rejects")}
            for r in rejected[:25]
        ]
        report.add_section("Rejected Traffic (top src/dst/port)", findings_table(rows, ["Source", "Destination", "Port", "Rejects"]))
    else:
        report.add_section("Rejected Traffic (top src/dst/port)", "No rejected flows in this window.")

    scan_candidates = flow.get("port_scan_candidates", [])
    if scan_candidates:
        rows = [{"Source": r.get("srcAddr"), "Distinct destination ports": r.get("distinctPorts")} for r in scan_candidates]
        report.add_section(
            "Possible Port Scan Activity",
            f"Sources contacting >= {nt.PORT_SCAN_DISTINCT_PORT_THRESHOLD} distinct destination ports in the window:\n\n"
            + findings_table(rows, ["Source", "Distinct destination ports"]),
        )
    else:
        report.add_section("Possible Port Scan Activity", "No source exceeded the distinct-destination-port threshold.")

    external_egress = flow.get("top_external_egress", [])
    if external_egress:
        rows = [
            {"Source": r.get("srcAddr"), "External destination": r.get("dstAddr"), "Bytes": r.get("totalBytes")}
            for r in external_egress[:25]
        ]
        report.add_section("Top External Egress (non-RFC1918 destinations)", findings_table(rows, ["Source", "External destination", "Bytes"]))
    else:
        report.add_section("Top External Egress (non-RFC1918 destinations)", "No external egress observed in this window.")

    network_findings = data["NetworkFindings"]
    if network_findings:
        rows = [
            {"Type": f.get("Type", "?"), "Severity": _severity_label(f.get("Severity", 0)), "Resource": f.get("Resource", {}).get("ResourceType", "?")}
            for f in network_findings[:40]
        ]
        report.add_section("GuardDuty Network-Related Findings", findings_table(rows, ["Type", "Severity", "Resource"]))
    else:
        report.add_section("GuardDuty Network-Related Findings", "No active Recon/UnauthorizedAccess/Trojan/Backdoor findings.")

    return report


def _severity_label(score: float) -> str:
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    region = args.region or ctx.session.region_name or "us-east-1"

    data = collect(ctx, region, args.log_group, args.lookback_hours)

    if args.json_out:
        jsonutil.write(data, args.json_out)
        print(f"Raw traffic evidence JSON written to {args.json_out}")

    report = build_report(data, region, args.log_group)
    paths = report.save(args.output_dir, "network-traffic-analysis", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
