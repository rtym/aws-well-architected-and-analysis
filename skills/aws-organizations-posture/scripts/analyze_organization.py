#!/usr/bin/env python3
"""Assess AWS Organizations posture: is this account part of an org, what
member accounts exist, Service Control Policy coverage per account,
delegated administrator accounts, and whether GuardDuty/Security Hub are
centrally managed org-wide (a delegated admin with every member enrolled)
versus configured independently per account -- then render a
Markdown/HTML/PDF report.

Read-only. Must be run against the Organizations management account or a
delegated administrator account -- a plain member account will see
`IsOrganizationsMember: False` (this is a real, expected state, not an
error) or AccessDenied on most calls here.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from shared.awslib.cli import base_parser, formats_tuple, make_context  # noqa: E402
from shared.awslib.collectors import organizations  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Assess AWS Organizations posture: accounts, SCPs, delegated admins, org-wide security services.")
    return parser.parse_args(argv)


def collect(ctx, home_region: str) -> dict:
    return organizations.collect_organization_posture(ctx, home_region)


def build_report(posture: dict) -> Report:
    report = Report(title="AWS Organizations Posture")

    if not posture.get("IsOrganizationsMember"):
        report.add_section(
            "Organizations Membership",
            "This account is **not** part of an AWS Organization (or this "
            "identity lacks Organizations visibility). Every other section "
            "of this report is only meaningful for the management account "
            "or a delegated administrator -- re-run with credentials for "
            "one of those if a multi-account posture review was intended.",
        )
        return report

    org = posture.get("Organization") or {}
    accounts = posture.get("Accounts", [])
    policies = posture.get("ServiceControlPolicies", [])
    uncovered = posture.get("AccountsWithoutScpCoverage", [])
    delegated = posture.get("DelegatedAdministrators", [])

    report.add_section(
        "Organization Summary",
        "\n".join(
            [
                f"- **Master account:** {org.get('MasterAccountId', '?')}",
                f"- **Feature set:** {org.get('FeatureSet', '?')}",
                f"- **Member accounts:** {len(accounts)}",
                f"- **Service Control Policies defined:** {len(policies)}",
                f"- **Accounts with no direct SCP attachment:** {len(uncovered)}",
            ]
        ),
    )

    if accounts:
        status_counts: dict[str, int] = {}
        for a in accounts:
            status_counts[a.get("Status", "?")] = status_counts.get(a.get("Status", "?"), 0) + 1
        if len(status_counts) > 1 or "ACTIVE" not in status_counts:
            chart_uri = charts.bar_chart(list(status_counts), list(status_counts.values()), title="Accounts by status", ylabel="Count")
            report.add_section("Account Status", f"![Account status]({chart_uri})")

        rows = [{"Account ID": a.get("Id"), "Name": a.get("Name"), "Email": a.get("Email"), "Status": a.get("Status")} for a in accounts]
        report.add_section("Member Accounts", findings_table(rows, ["Account ID", "Name", "Email", "Status"]))

    if uncovered:
        rows = [{"Account ID": a.get("Id"), "Name": a.get("Name")} for a in uncovered]
        report.add_section(
            "Accounts Without a Directly-Attached SCP",
            "These accounts have no Service Control Policy attached directly "
            "to them -- they may still be covered by a policy attached at "
            "the OU or root level; this check only looks at direct account "
            "attachments, so treat this as a lead to verify, not a confirmed gap:\n\n"
            + findings_table(rows, ["Account ID", "Name"]),
        )
    else:
        report.add_section("Accounts Without a Directly-Attached SCP", "Every account has at least one directly-attached SCP.")

    if policies:
        rows = [{"Policy": p.get("Name"), "Description": p.get("Description", ""), "Direct account targets": len([t for t in p.get("_Targets", []) if t.get("Type") == "ACCOUNT"])} for p in policies]
        report.add_section("Service Control Policies", findings_table(rows, ["Policy", "Description", "Direct account targets"]))

    if delegated:
        rows = [{"Account ID": d.get("Id"), "Name": d.get("Name"), "Email": d.get("Email")} for d in delegated]
        report.add_section("Delegated Administrator Accounts", findings_table(rows, ["Account ID", "Name", "Email"]))
    else:
        report.add_section("Delegated Administrator Accounts", "No delegated administrator accounts registered for any AWS service.")

    gd_admin = posture.get("GuardDutyOrganizationAdmin")
    sh_admin = posture.get("SecurityHubOrganizationAdmin")
    report.add_section(
        "Org-Wide Security Service Management",
        "\n".join(
            [
                f"- **GuardDuty delegated administrator:** {gd_admin.get('AdminAccountId') if gd_admin else 'NOT configured -- each account manages GuardDuty independently'}",
                f"- **Security Hub delegated administrator:** {sh_admin.get('AccountId') if sh_admin else 'NOT configured -- each account manages Security Hub independently'}",
            ]
        ),
    )

    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    home_region = args.region or "us-east-1"

    posture = collect(ctx, home_region)

    if args.json_out:
        jsonutil.write(posture, args.json_out)
        print(f"Raw organizations posture JSON written to {args.json_out}")

    report = build_report(posture)
    paths = report.save(args.output_dir, "organizations-posture", formats_tuple(args.formats))
    for fmt, path in paths.items():
        print(f"Wrote {fmt.upper()} report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
