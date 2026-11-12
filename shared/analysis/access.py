"""Calls the run was not allowed to make.

A collector that is denied returns the same empty value it returns when
there is nothing to find, so `AwsContext` keeps a list of the denied calls
(`ctx.denied`). Scripts save that list in the evidence as `AccessDenied`,
the scored checks treat the evidence behind it as unread, and every report
lists it in an Access Gaps section so an empty table can be told apart
from one the scan couldn't fill.
"""
from __future__ import annotations

from ..reporting.report import findings_table

KEY = "AccessDenied"
SECTION_TITLE = "Access Gaps"


def denied_calls(ctx) -> list[dict]:
    """The denied calls recorded on `ctx` so far, as a new list."""
    return list(getattr(ctx, "denied", None) or [])


def denied(data: dict) -> list[dict]:
    return (data or {}).get(KEY) or []


def was_denied(data: dict, *collectors: str) -> bool:
    """True when any of the named collectors was denied in any region."""
    return any(d.get("Collector") in collectors for d in denied(data))


def _rows(entries: list[dict]) -> list[dict]:
    """One row per collector, operation and error, with the regions (and
    resources, for per-resource denials) it was denied in."""
    grouped: dict[tuple, dict] = {}
    for d in entries:
        key = (d.get("Collector"), d.get("Operation"), d.get("Code"))
        group = grouped.setdefault(key, {"regions": [], "resources": []})
        if d.get("Region") not in group["regions"]:
            group["regions"].append(d.get("Region"))
        if d.get("Resource"):
            group["resources"].append(d["Resource"])
    rows = []
    for (collector, operation, code), group in grouped.items():
        resources = group["resources"]
        shown = ", ".join(resources[:5]) + (f" and {len(resources) - 5} more" if len(resources) > 5 else "")
        rows.append(
            {
                "Denied call": operation or "?",
                "Collector": str(collector).replace("_", " "),
                "Where": ", ".join(str(r) for r in group["regions"]) + (f" ({shown})" if shown else ""),
                "Error": code or "?",
            }
        )
    return rows


def section_body(entries: list[dict]) -> str:
    return (
        "The scan was denied these calls, so the evidence behind them is unread, not empty. "
        "Scored checks that depend on it show NO DATA, and counts elsewhere in this report "
        "leave it out. Grant the read-only actions listed in the plugin's `PERMISSIONS.md` "
        "and run the scan again to fill the gaps.\n\n"
        + findings_table(_rows(entries), ["Denied call", "Collector", "Where", "Error"])
    )


def add_section(report, data: dict, level: int = 2) -> bool:
    """Append the Access Gaps section when anything was denied."""
    entries = denied(data)
    if not entries:
        return False
    report.add_section(SECTION_TITLE, section_body(entries), level=level)
    return True
