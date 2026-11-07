"""The scoring and prioritization engine every scored report shares."""
import pytest

from shared.analysis import checks as engine
from shared.analysis.checks import Affected, AttackPath, Check, Threat


def _check(cid="c", severity="HIGH", domain="D", effort="Low", **kw):
    return Check(cid, f"{cid} passes", domain, severity, f"fix {cid}", effort, **kw)


def test_evaluate_maps_none_empty_and_affected_to_the_three_statuses():
    catalog = [
        (_check("missing"), lambda d: None),
        (_check("clean"), lambda d: []),
        (_check("broken"), lambda d: [Affected("r1", "us-east-1")]),
    ]
    statuses = {r.check.id: r.status for r in engine.evaluate(catalog, {})}
    assert statuses == {"missing": engine.NO_DATA, "clean": engine.PASS, "broken": engine.FAIL}


def test_score_follows_security_hub_and_leaves_no_data_out():
    results = engine.evaluate(
        [
            (_check("a"), lambda d: []),
            (_check("b"), lambda d: []),
            (_check("c"), lambda d: [Affected("x")]),
            (_check("d"), lambda d: None),
        ],
        {},
    )
    s = engine.score(results)
    assert (s.score, s.passed, s.failed, s.no_data, s.evaluated) == (67, 2, 1, 1, 3)


def test_score_is_none_when_nothing_had_data():
    assert engine.score(engine.evaluate([(_check(), lambda d: None)], {})).score is None
    assert engine.score([]).score is None


@pytest.mark.parametrize(
    "value, band",
    [(None, "Not evaluated"), (100, "Strong"), (90, "Strong"), (89, "Fair"), (70, "Fair"), (69, "Weak"), (50, "Weak"), (49, "Poor"), (0, "Poor")],
)
def test_band_thresholds_line_up_with_tone_colors(value, band):
    assert engine.band(value) == band


def test_check_rejects_unknown_severity_or_effort():
    with pytest.raises(ValueError, match="severity"):
        _check(severity="URGENT")
    with pytest.raises(ValueError, match="effort"):
        _check(effort="Trivial")


def test_check_reference_marks_related_controls():
    assert _check(control="EC2.8").reference == "EC2.8"
    assert _check(control="Config.1", exact=False).reference == "Config.1 (related)"
    assert _check().reference == "--"


@pytest.mark.parametrize(
    "affected, expected",
    [
        ([], "--"),
        ([Affected("account", "global")], "account-wide"),
        ([Affected("root user", "global")], "root user"),
        ([Affected("alice"), Affected("bob")], "2 resources"),
        ([Affected("us-east-1", "us-east-1")], "1 region"),
        ([Affected("us-east-1", "us-east-1"), Affected("eu-west-1", "eu-west-1")], "2 regions"),
        ([Affected("sg-1", "us-east-1")], "1 resource in us-east-1"),
        ([Affected("sg-1", "us-east-1"), Affected("sg-2", "us-east-1")], "2 resources in us-east-1"),
        ([Affected("sg-1", "us-east-1"), Affected("sg-2", "eu-west-1"), Affected("sg-3", "eu-west-1")], "3 resources in 2 regions"),
    ],
)
def test_scope_text(affected, expected):
    assert engine.scope_text(affected) == expected


def test_prioritize_orders_by_severity_then_kind_then_domain_then_blast_radius_then_effort():
    results = engine.evaluate(
        [
            (_check("medium", "MEDIUM"), lambda d: [Affected("x")] * 9),
            (_check("crit-visibility", "CRITICAL", domain="Detection"), lambda d: [Affected("x")]),
            (_check("crit-exposure-costly", "CRITICAL", domain="Network", effort="High"), lambda d: [Affected("x")]),
            (_check("crit-exposure-cheap", "CRITICAL", domain="Network"), lambda d: [Affected("x")]),
            (_check("crit-exposure-wide", "CRITICAL", domain="Network", effort="High"), lambda d: [Affected("x")] * 3),
            (_check("passing", "CRITICAL"), lambda d: []),
        ],
        {},
    )
    path = AttackPath("p", "path", "CRITICAL", "why", "fix the path", [Affected("i-1", "us-east-1")])
    threat = Threat("threat", "CRITICAL", "investigate", [Affected("i-2", "us-east-1")])
    actions = engine.prioritize(results, [path], [threat], limit=None, domain_order=("Network", "Detection"))
    assert [a.action for a in actions] == [
        "fix the path",
        "investigate",
        "fix crit-exposure-wide",
        "fix crit-exposure-cheap",
        "fix crit-exposure-costly",
        "fix crit-visibility",
        "fix medium",
    ]
    assert [a.priority for a in actions] == list(range(1, 8))
    assert [a.kind for a in actions[:3]] == ["attack path", "threat", "check"]


def test_prioritize_limits_and_uses_the_failure_wording():
    results = engine.evaluate(
        [(Check(f"c{i}", "passes", "D", "LOW", "fix", finding=f"broken {i}"), lambda d: [Affected("x")]) for i in range(12)],
        {},
    )
    actions = engine.prioritize(results)
    assert len(actions) == 10
    assert actions[0].why == "broken 0"


def test_severity_counts_cover_every_level():
    results = engine.evaluate(
        [(_check("a", "HIGH"), lambda d: [Affected("x")]), (_check("b", "LOW"), lambda d: [])],
        {},
    )
    assert engine.severity_counts(results) == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}


def test_to_dict_is_json_ready_and_complete():
    import json

    results = engine.evaluate(
        [
            (_check("a", control="EC2.8", question="SEC06", domain="Network"), lambda d: [Affected("i-1", "us-east-1", "running")]),
            (_check("b", domain="Data"), lambda d: None),
        ],
        {},
    )
    path = AttackPath("p", "path", "HIGH", "why", "fix", [Affected("x")], ("a",))
    out = engine.to_dict(results, [path], engine.prioritize(results, [path]))
    json.dumps(out)
    assert out["Score"]["Value"] == 0 and out["Score"]["NoData"] == 1
    assert out["DomainScores"]["Data"]["Value"] is None
    check_a = out["Checks"][0]
    assert check_a["Control"] == "EC2.8" and check_a["WellArchitectedQuestion"] == "SEC06"
    assert check_a["Affected"] == [{"resource": "i-1", "region": "us-east-1", "detail": "running"}]
    assert out["AttackPaths"][0]["BuildsOn"] == ["a"]
    assert [a["kind"] for a in out["PriorityActions"]] == ["attack path", "check"]
