"""A small engine for turning collected evidence into scored, prioritized
findings. Skill scripts define a catalog of `Check`s plus the function that
finds the affected resources for each one; this module does the rest the
same way for every report:

- a check with no data is NO DATA, with nothing affected is PASS, and with
  at least one affected resource is FAIL;
- the score is passed checks divided by checks with data, the method
  Security Hub uses for its security score (NO DATA is left out of both);
- `AttackPath`s are correlations of several gaps on the same resource or
  region that make each other worse, and rank ahead of single checks at
  the same severity;
- `prioritize` merges attack paths, active threats, and failed checks into
  one ordered action list.

Nothing here calls AWS. It only reads the evidence dicts the collectors
already produced, so it runs the same on live data and on a saved
`--json-out` file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
EFFORTS = ("Low", "Medium", "High")
EFFORT_RANK = {e: i for i, e in enumerate(EFFORTS)}

PASS = "PASS"
FAIL = "FAIL"
NO_DATA = "NO DATA"


@dataclass(frozen=True)
class Check:
    """One pass/fail test. `title` states the passing condition ("GuardDuty
    is enabled in every scanned region") and `finding` the failure
    ("GuardDuty is off in some regions"); `remediation` is the imperative
    fix. `control` names the Security Hub control the check implements;
    `exact=False` marks a check that covers the same risk with a narrower
    or different test than that control."""

    id: str
    title: str
    domain: str
    severity: str
    remediation: str
    effort: str = "Low"
    control: str | None = None
    exact: bool = True
    question: str | None = None
    finding: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"{self.id}: unknown severity {self.severity!r}")
        if self.effort not in EFFORT_RANK:
            raise ValueError(f"{self.id}: unknown effort {self.effort!r}")

    @property
    def reference(self) -> str:
        if not self.control:
            return "--"
        return self.control if self.exact else f"{self.control} (related)"


@dataclass
class Affected:
    resource: str
    region: str = "global"
    detail: str = ""


@dataclass
class CheckResult:
    check: Check
    status: str
    affected: list[Affected] = field(default_factory=list)
    note: str = ""

    @property
    def failed(self) -> bool:
        return self.status == FAIL


@dataclass
class AttackPath:
    """Gaps that combine into a direct route to compromise: an
    internet-reachable host that also allows IMDSv1, exposed resources in a
    region with no threat detection. `builds_on` lists the check IDs
    involved."""

    id: str
    title: str
    severity: str
    why: str
    remediation: str
    affected: list[Affected]
    builds_on: tuple[str, ...] = ()
    effort: str = "Medium"


@dataclass
class Threat:
    """An active detection (a GuardDuty finding type, open Security Hub
    findings) that needs investigation rather than a configuration fix."""

    title: str
    severity: str
    action: str
    affected: list[Affected]
    reference: str = "--"


@dataclass
class Action:
    priority: int
    severity: str
    action: str
    why: str
    scope: str
    reference: str
    effort: str
    kind: str  # "attack path", "threat", or "check"


@dataclass
class Score:
    score: int | None
    passed: int
    failed: int
    no_data: int

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed


def evaluate(catalog: list[tuple[Check, Callable[[dict], list[Affected] | None]]], data: dict) -> list[CheckResult]:
    """Run every check against the evidence. An evaluator returns None when
    the evidence doesn't contain what it needs (an older JSON file, a
    service that couldn't be read), [] when nothing is affected, or the
    affected resources."""
    results = []
    for check, evaluator in catalog:
        affected = evaluator(data)
        if affected is None:
            results.append(CheckResult(check, NO_DATA))
        elif affected:
            results.append(CheckResult(check, FAIL, list(affected)))
        else:
            results.append(CheckResult(check, PASS))
    return results


def score(results: list[CheckResult]) -> Score:
    passed = sum(1 for r in results if r.status == PASS)
    failed = sum(1 for r in results if r.status == FAIL)
    no_data = sum(1 for r in results if r.status == NO_DATA)
    value = round(100 * passed / (passed + failed)) if passed + failed else None
    return Score(value, passed, failed, no_data)


def band(value: int | None) -> str:
    """Word bands that line up with the report's tone colors: Strong is
    green, Fair amber, Weak and Poor red."""
    if value is None:
        return "Not evaluated"
    if value >= 90:
        return "Strong"
    if value >= 70:
        return "Fair"
    if value >= 50:
        return "Weak"
    return "Poor"


def scores_by_domain(results: list[CheckResult]) -> dict[str, Score]:
    domains: dict[str, list[CheckResult]] = {}
    for r in results:
        domains.setdefault(r.check.domain, []).append(r)
    return {name: score(rs) for name, rs in domains.items()}


def scope_text(affected: list[Affected]) -> str:
    """"account-wide", "2 regions", "1 resource in us-east-1", "4 resources
    in 2 regions". A region-level gap (a service off in a region) names the
    region as its resource and is counted as a region."""
    if not affected:
        return "--"
    if all(a.resource == a.region and a.region != "global" for a in affected):
        n = len({a.region for a in affected})
        return f"{n} region" if n == 1 else f"{n} regions"
    regions = sorted({a.region for a in affected if a.region != "global"})
    resources = len(affected)
    if not regions:
        if resources == 1:
            return "account-wide" if affected[0].resource == "account" else affected[0].resource
        return f"{resources} resources"
    noun = "resource" if resources == 1 else "resources"
    if len(regions) == 1:
        return f"{resources} {noun} in {regions[0]}"
    return f"{resources} {noun} in {len(regions)} regions"


def prioritize(
    results: list[CheckResult],
    paths: list[AttackPath] = (),
    threats: list[Threat] = (),
    limit: int | None = 10,
    domain_order: tuple[str, ...] = (),
) -> list[Action]:
    """One ordered to-do list. Most severe first; at equal severity an
    attack path outranks an active threat, which outranks a single failed
    check; failed checks then follow `domain_order` (direct exposure before
    missing visibility, say), then the larger blast radius, then the
    cheaper fix."""
    domain_rank = {d: i for i, d in enumerate(domain_order)}
    candidates: list[tuple[tuple, Action]] = []
    for p in paths:
        candidates.append(
            (
                (SEVERITY_RANK[p.severity], 0, 0, -len(p.affected), EFFORT_RANK.get(p.effort, 1)),
                Action(0, p.severity, p.remediation, p.title, scope_text(p.affected), "attack path", p.effort, "attack path"),
            )
        )
    for t in threats:
        candidates.append(
            (
                (SEVERITY_RANK[t.severity], 1, 0, -len(t.affected), 0),
                Action(0, t.severity, t.action, t.title, scope_text(t.affected), t.reference, "Medium", "threat"),
            )
        )
    for r in results:
        if not r.failed:
            continue
        c = r.check
        candidates.append(
            (
                (SEVERITY_RANK[c.severity], 2, domain_rank.get(c.domain, len(domain_rank)), -len(r.affected), EFFORT_RANK[c.effort]),
                Action(0, c.severity, c.remediation, c.finding or c.title, scope_text(r.affected), c.reference, c.effort, "check"),
            )
        )
    candidates.sort(key=lambda pair: pair[0])
    chosen = [action for _, action in candidates][: limit if limit else None]
    for n, action in enumerate(chosen, start=1):
        action.priority = n
    return chosen


def severity_counts(results: list[CheckResult]) -> dict[str, int]:
    """Failed checks per severity, every level present (zero included)."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        if r.failed:
            counts[r.check.severity] += 1
    return counts


def to_dict(results: list[CheckResult], paths: list[AttackPath] = (), actions: list[Action] = ()) -> dict:
    """JSON-ready form, saved into the evidence file so the gap-analysis
    skill can cite check results without recomputing them."""
    overall = score(results)
    return {
        "Score": {
            "Value": overall.score,
            "Band": band(overall.score),
            "Passed": overall.passed,
            "Failed": overall.failed,
            "NoData": overall.no_data,
            "Method": "passed / (passed + failed); NO DATA excluded (Security Hub's security score method)",
        },
        "DomainScores": {
            name: {"Value": s.score, "Passed": s.passed, "Failed": s.failed, "NoData": s.no_data}
            for name, s in scores_by_domain(results).items()
        },
        "Checks": [
            {
                "Id": r.check.id,
                "Title": r.check.title,
                "Finding": r.check.finding,
                "Domain": r.check.domain,
                "Severity": r.check.severity,
                "Status": r.status,
                "Control": r.check.control,
                "ControlMatchesExactly": r.check.exact,
                "WellArchitectedQuestion": r.check.question,
                "Remediation": r.check.remediation,
                "Effort": r.check.effort,
                "Note": r.note,
                "Affected": [vars(a) for a in r.affected],
            }
            for r in results
        ],
        "AttackPaths": [
            {
                "Id": p.id,
                "Title": p.title,
                "Severity": p.severity,
                "Why": p.why,
                "Remediation": p.remediation,
                "BuildsOn": list(p.builds_on),
                "Affected": [vars(a) for a in p.affected],
            }
            for p in paths
        ],
        "PriorityActions": [vars(a) for a in actions],
    }
