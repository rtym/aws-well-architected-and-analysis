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

from shared.analysis import access  # noqa: E402
from shared.awslib.cli import base_parser, formats_tuple, make_context, run  # noqa: E402
from shared.awslib.collectors import organizations  # noqa: E402
from shared.reporting import charts, jsonutil  # noqa: E402
from shared.reporting.report import Report, findings_table  # noqa: E402


def parse_args(argv=None) -> argparse.Namespace:
    parser = base_parser("Assess AWS Organizations posture: accounts, SCPs, delegated admins, org-wide security services.")
    return parser.parse_args(argv)


def collect(ctx, home_region: str) -> dict:
    posture = organizations.collect_organization_posture(ctx, home_region)
    # Calls the run was denied; the report lists them under Access Gaps.
    posture[access.KEY] = access.denied_calls(ctx)
    return posture


# The collector behind each part of the report. A denied collector returns
# the same empty value as "nothing there", so each part checks its own
# collector before it says "no accounts", "no SCP", or "not configured".
ACCOUNTS = "list_accounts"
POLICIES = "list_service_control_policies"
OU_MEMBERS = "ou_descendant_account_ids"
DELEGATED = "list_delegated_administrators"
ORG_ADMINS = {"GuardDutyOrganizationAdmin": "guardduty_organization_admin", "SecurityHubOrganizationAdmin": "securityhub_organization_admin"}
NOT_READ = "unknown: the scan was denied the call (see Access Gaps)"


def _denied(posture: dict, collector: str) -> bool:
    return access.was_denied(posture, collector)


def _add_kpis(report: Report, posture: dict) -> None:
    org = posture.get("Organization") or {}
    accounts = posture.get("Accounts", [])
    uncovered = posture.get("AccountsWithoutScpCoverage", [])
    members = [a for a in accounts if a.get("Id") != org.get("MasterAccountId")]
    active = sum(1 for a in accounts if a.get("Status", "ACTIVE") == "ACTIVE")
    if _denied(posture, ACCOUNTS):
        report.add_kpi("Accounts", "n/a", "access denied")
    else:
        report.add_kpi("Accounts", len(accounts), f"{active} active", "neutral")
    if _denied(posture, POLICIES):
        report.add_kpi("SCP coverage", "n/a", "access denied")
    elif members:
        covered = len(members) - len(uncovered)
        pct = round(100 * covered / len(members))
        partial = _denied(posture, OU_MEMBERS)
        # With an OU's accounts unread, accounts under it count as
        # uncovered, so the percentage is a lower bound.
        report.add_kpi(
            "SCP coverage",
            f"{pct}%",
            f"{covered} of {len(members)} member accounts" + (", at least: some OUs unread" if partial else ""),
            "good" if pct == 100 else "warn" if pct >= 75 or partial else "bad",
        )
    restrictive = organizations.restrictive_scps(posture.get("ServiceControlPolicies", []))
    if _denied(posture, POLICIES):
        report.add_kpi("Restrictive SCPs", "n/a", "access denied")
    else:
        report.add_kpi("Restrictive SCPs", len(restrictive), "excluding FullAWSAccess", "good" if restrictive else "bad")
    if _denied(posture, DELEGATED):
        report.add_kpi("Delegated admins", "n/a", "access denied")
    else:
        report.add_kpi("Delegated admins", len(posture.get("DelegatedAdministrators", [])), "registered accounts")
    for label, key in (("GuardDuty", "GuardDutyOrganizationAdmin"), ("Security Hub", "SecurityHubOrganizationAdmin")):
        managed = bool(posture.get(key))
        if not managed and _denied(posture, ORG_ADMINS[key]):
            report.add_kpi(f"{label} org-managed", "n/a", "access denied")
            continue
        report.add_kpi(
            f"{label} org-managed",
            "yes" if managed else "no",
            "delegated administrator set" if managed else "configured per account",
            "good" if managed else "warn",
        )


def build_report(posture: dict) -> Report:
    report = Report(
        title="AWS Organizations Posture",
        intro=(
            "This report covers the governance layer above any single "
            "account: whether this account belongs to an AWS Organization, "
            "which member accounts exist, where Service Control Policies "
            "are attached, and whether GuardDuty and Security Hub are "
            "managed centrally for the whole organization. Start with the "
            "Organization Summary; the sections below it carry the "
            "per-account detail."
        ),
    )

    if not posture.get("IsOrganizationsMember"):
        report.add_section(
            "Organizations Membership",
            "This account is **not** part of an AWS Organization (or this "
            "identity lacks Organizations visibility). Every other section "
            "of this report is only meaningful for the management account "
            "or a delegated administrator -- re-run with credentials for "
            "one of those if a multi-account posture review was intended.",
        )
        access.add_section(report, posture)
        return report

    org = posture.get("Organization") or {}
    accounts = posture.get("Accounts", [])
    policies = posture.get("ServiceControlPolicies", [])
    uncovered = posture.get("AccountsWithoutScpCoverage", [])
    delegated = posture.get("DelegatedAdministrators", [])
    _add_kpis(report, posture)

    report.add_section(
        "Organization Summary",
        "\n".join(
            [
                # The API field is still MasterAccountId; AWS's current term
                # for it is "management account".
                f"- **Management account:** {org.get('MasterAccountId', '?')}",
                f"- **Feature set:** {org.get('FeatureSet', '?')}",
                f"- **Accounts:** {NOT_READ if _denied(posture, ACCOUNTS) else len(accounts)}",
                f"- **Service Control Policies defined:** {NOT_READ if _denied(posture, POLICIES) else len(policies)}",
                f"- **Member accounts with no restrictive SCP in effect:** "
                f"{NOT_READ if _denied(posture, ACCOUNTS) or _denied(posture, POLICIES) else len(uncovered)}",
            ]
        ),
    )

    if accounts:
        status_counts: dict[str, int] = {}
        for a in accounts:
            status_counts[a.get("Status", "?")] = status_counts.get(a.get("Status", "?"), 0) + 1
        if len(status_counts) > 1 or "ACTIVE" not in status_counts:
            chart_uri = charts.bar_chart(list(status_counts), list(status_counts.values()), title="Accounts by status", horizontal=True)
            report.add_section("Account Status", f"![Account status]({chart_uri})")

        rows = [{"Account ID": a.get("Id"), "Name": a.get("Name"), "Email": a.get("Email"), "Status": a.get("Status")} for a in accounts]
        report.add_section("Member Accounts", findings_table(rows, ["Account ID", "Name", "Email", "Status"]))

    coverage_note = (
        "Coverage counts every SCP except AWS's allow-all FullAWSAccess, "
        "whether attached to the account itself, to an OU above it, or to the "
        "root. The management account is not listed: SCPs never apply to it."
    )
    if _denied(posture, ACCOUNTS) or _denied(posture, POLICIES):
        report.add_section(
            "Accounts With No Restrictive SCP in Effect",
            "Not evaluated: the scan was denied the account or policy listing it needs "
            "(see Access Gaps). Run it from the management account or a delegated "
            f"administrator. {coverage_note}",
        )
    elif uncovered:
        rows = [{"Account ID": a.get("Id"), "Name": a.get("Name")} for a in uncovered]
        ou_note = (
            "\n\nThe scan was denied the account list of some OUs (see Access Gaps), so an "
            "account below may be covered by an SCP attached to one of those OUs."
            if _denied(posture, OU_MEMBERS)
            else ""
        )
        report.add_section(
            "Accounts With No Restrictive SCP in Effect",
            "These member accounts run with no guardrail beyond IAM: no SCP "
            f"restricts what their principals can do. {coverage_note}{ou_note}\n\n"
            + findings_table(rows, ["Account ID", "Name"]),
        )
    else:
        report.add_section(
            "Accounts With No Restrictive SCP in Effect",
            f"Every member account has at least one restrictive SCP in effect. {coverage_note}",
        )

    if policies:
        def _targets(policy: dict, kind: str) -> int:
            return len([t for t in policy.get("_Targets", []) if t.get("Type") == kind])

        rows = [
            {
                "Policy": p.get("Name"),
                "Description": p.get("Description", ""),
                "Root": _targets(p, "ROOT"),
                "OUs": _targets(p, "ORGANIZATIONAL_UNIT"),
                "Accounts": _targets(p, "ACCOUNT"),
            }
            for p in policies
        ]
        report.add_section(
            "Service Control Policies",
            "Where each policy is attached (an attachment to the root or an OU "
            "applies to every account beneath it):\n\n"
            + findings_table(rows, ["Policy", "Description", "Root", "OUs", "Accounts"]),
        )

    if delegated:
        rows = [{"Account ID": d.get("Id"), "Name": d.get("Name"), "Email": d.get("Email")} for d in delegated]
        report.add_section("Delegated Administrator Accounts", findings_table(rows, ["Account ID", "Name", "Email"]))
    elif _denied(posture, DELEGATED):
        report.add_section("Delegated Administrator Accounts", f"Delegated administrators: {NOT_READ}.")
    else:
        report.add_section("Delegated Administrator Accounts", "No delegated administrator accounts registered for any AWS service.")

    def admin_line(label: str, key: str, id_field: str) -> str:
        admin = posture.get(key)
        if admin:
            value = admin.get(id_field)
        elif _denied(posture, ORG_ADMINS[key]):
            value = NOT_READ
        else:
            value = f"NOT configured -- each account manages {label} independently"
        return f"- **{label} delegated administrator:** {value}"

    report.add_section(
        "Org-Wide Security Service Management",
        "\n".join(
            [
                admin_line("GuardDuty", "GuardDutyOrganizationAdmin", "AdminAccountId"),
                admin_line("Security Hub", "SecurityHubOrganizationAdmin", "AccountId"),
            ]
        ),
    )

    access.add_section(report, posture)
    return report


def main(argv=None) -> int:
    args = parse_args(argv)
    ctx = make_context(args)
    home_region = ctx.home_region()

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
    raise SystemExit(run(main))
