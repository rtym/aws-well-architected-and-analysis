"""A denied call is unread evidence, not empty evidence.

Collectors return the same empty default when a call is denied as when
there is nothing to find. Before 1.7.0 that default was scored as written:
a role without `ec2:DescribeVolumes` passed "every EBS volume is encrypted",
and one without `guardduty:ListDetectors` failed "GuardDuty is enabled".
These tests pin the path from the denied call to the report: recorded on
the context, saved in the evidence, scored as NO DATA, listed for the reader.
"""
import copy

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from shared.analysis import access, dr_checks
from shared.analysis import checks as engine
from shared.analysis import security_checks as sc
from shared.awslib.collectors import data_stores, security
from shared.awslib.session import PERMISSION_DENIED_CODES, AwsContext, ignore_access_denied
from shared.reporting.report import Report
from tests.stub_helpers import install_stub
from tests.test_analysis_dr_checks import dr_bundle
from tests.test_analysis_security_checks import clean_bundle


def _raise(code: str, operation: str = "ListThings", message: str = "no"):
    raise ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _denied(collector: str, region: str = "us-east-1", **extra) -> dict:
    return {"Collector": collector, "Operation": "Op", "Region": region, "Code": "AccessDenied", **extra}


# ------------------------------------------------------------------ recording
@pytest.mark.parametrize("code", sorted(PERMISSION_DENIED_CODES))
def test_a_permission_error_is_recorded_on_the_context(ctx, code):
    @ignore_access_denied(default=list)
    def list_things(ctx, region):
        _raise(code)

    assert list_things(ctx, "eu-west-1") == []
    assert ctx.denied == [{"Collector": "list_things", "Operation": "ListThings", "Region": "eu-west-1", "Code": code}]


@pytest.mark.parametrize("code", ["OptInRequired", "InvalidAccessException", "AWSOrganizationsNotInUseException", "DataUnavailableException"])
def test_a_service_not_in_use_is_an_answer_and_is_not_recorded(ctx, code):
    @ignore_access_denied(default=list)
    def list_things(ctx, region):
        _raise(code)

    assert list_things(ctx, "us-east-1") == []
    assert ctx.denied == []


def test_the_same_denial_is_recorded_once_and_account_wide_calls_are_global(ctx):
    @ignore_access_denied(default=list)
    def list_things(ctx):
        _raise("AccessDenied")

    @ignore_access_denied(default=list)
    def trails(ctx, home_region):
        _raise("AccessDenied", "DescribeTrails")

    list_things(ctx)
    list_things(ctx=ctx)
    trails(ctx, "eu-west-1")
    assert [(d["Collector"], d["Region"]) for d in ctx.denied] == [("list_things", "global"), ("trails", "eu-west-1")]


def test_a_helper_without_a_context_still_swallows_the_error():
    @ignore_access_denied(default=lambda: None)
    def read(client, name):
        _raise("AccessDenied")

    assert read(object(), "x") is None


def test_denied_calls_copies_the_list_and_tolerates_a_context_without_one(ctx):
    ctx.record_denied("c", None, "AccessDenied")
    copied = access.denied_calls(ctx)
    copied.append("x")
    assert len(ctx.denied) == 1
    assert access.denied_calls(object()) == []
    assert access.denied(None) == [] and access.denied({}) == []


# ----------------------------------------------------------------- collectors
def test_real_collector_denial_names_the_operation_and_region(ctx):
    _, stub = install_stub(ctx, "ec2", region="eu-west-1")
    stub.add_client_error("describe_volumes", service_error_code="UnauthorizedOperation")
    assert security.unencrypted_ebs_volumes(ctx, "eu-west-1") == []
    assert ctx.denied == [
        {"Collector": "unencrypted_ebs_volumes", "Operation": "DescribeVolumes", "Region": "eu-west-1", "Code": "UnauthorizedOperation"}
    ]


def test_macie_never_enabled_is_off_but_a_real_denial_is_recorded(ctx):
    _, stub = install_stub(ctx, "macie2", region="us-east-1")
    stub.add_client_error("get_macie_session", service_error_code="AccessDeniedException", service_message="Macie is not enabled.")
    stub.add_client_error(
        "get_macie_session",
        service_error_code="AccessDeniedException",
        service_message="User: arn:aws:iam::1:user/u is not authorized to perform: macie2:GetMacieSession",
    )
    assert security.macie_status(ctx, "us-east-1") == {"Enabled": False, "Status": None}
    assert ctx.denied == []
    assert security.macie_status(ctx, "us-east-1") == {"Enabled": False, "Status": None}
    assert [d["Collector"] for d in ctx.denied] == ["macie_status"]


def test_macie_other_errors_still_raise(ctx):
    _, stub = install_stub(ctx, "macie2", region="us-east-1")
    stub.add_client_error("get_macie_session", service_error_code="ThrottlingException")
    with pytest.raises(ClientError):
        security.macie_status(ctx, "us-east-1")


@mock_aws
def test_a_bucket_whose_settings_cannot_be_read_is_not_reported_public_or_unencrypted(ctx, monkeypatch):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="locked-out")
    s3.create_bucket(Bucket="readable")

    real_pab = data_stores._bucket_public_access_block.__wrapped__
    real_enc = data_stores._bucket_encryption.__wrapped__

    def deny_locked(real):
        @ignore_access_denied(default=lambda: data_stores._UNREADABLE)
        def reader(client, name):
            if name == "locked-out":
                _raise("AccessDenied")
            return real(client, name)

        return reader

    monkeypatch.setattr(
        data_stores,
        "_BUCKET_SETTINGS",
        (
            ("PublicAccessBlock", deny_locked(real_pab)),
            ("Encryption", deny_locked(real_enc)),
            ("Versioning", data_stores._bucket_versioning),
            ("Replication", data_stores._bucket_replication),
        ),
    )
    found = data_stores.collect_global_data_stores(ctx)
    by_name = {b["Name"]: b for b in found["S3Buckets"]}
    assert by_name["locked-out"]["_Unreadable"] == ["PublicAccessBlock", "Encryption"]
    assert by_name["locked-out"]["_PublicAccessBlock"] is None
    assert "_Unreadable" not in by_name["readable"]
    assert found["BucketsNotRead"] == [{"Name": "locked-out", "Settings": ["PublicAccessBlock", "Encryption"]}]
    # The readable bucket has no Block Public Access, so it is listed; the
    # unreadable one must not be, in either list.
    assert [b["Name"] for b in found["PubliclyAccessibleBuckets"]] == ["readable"]
    assert "locked-out" not in [b["Name"] for b in found["UnencryptedBuckets"]]
    assert ctx.denied == [
        {
            "Collector": "list_buckets",
            "Operation": "GetPublicAccessBlock, GetBucketEncryption",
            "Region": "us-east-1",
            "Code": "AccessDenied",
            "Resource": "locked-out",
        }
    ]


# ------------------------------------------------------------ security checks
def _status(data) -> dict:
    return {r.check.id: r.status for r in sc.evaluate_checks(data)}


def _result(data, check_id):
    return next(r for r in sc.evaluate_checks(data) if r.check.id == check_id)


# What each collector returns when denied, and the check that used to
# mis-score it: PASS for an empty list, FAIL for a service reported off.
DENIED_CASES = [
    ("guardduty_detector_ids", {"GuardDuty": {"Enabled": False, "DetectorIds": []}}, "guardduty-enabled", engine.FAIL),
    ("securityhub_status", {"SecurityHub": {"Enabled": False}}, "securityhub-enabled", engine.FAIL),
    ("inspector2_status", {"Inspector2": {"Enabled": False, "Status": None}}, "inspector-enabled", engine.FAIL),
    ("macie_status", {"Macie": {"Enabled": False, "Status": None}}, "macie-enabled", engine.FAIL),
    ("config_recorder_status", {"ConfigRecorder": {"Recorders": [], "Recording": False}}, "config-recording", engine.FAIL),
    ("access_analyzer_findings", {}, "access-analyzer-findings", engine.PASS),
    ("unencrypted_ebs_volumes", {}, "ebs-volume-encryption", engine.PASS),
    ("public_ebs_snapshots", {}, "ebs-snapshot-public", engine.PASS),
    ("kms_keys_without_rotation", {}, "kms-rotation", engine.PASS),
    ("lambda_urls_without_auth", {}, "lambda-url-auth", engine.PASS),
    ("describe_rds_instances", {}, "rds-public", engine.PASS),
    ("describe_rds_instances", {}, "rds-encryption", engine.PASS),
    ("describe_rds_snapshots", {}, "rds-snapshot-public", engine.PASS),
    ("public_rds_snapshots", {}, "rds-snapshot-public", engine.PASS),
    ("public_rds_cluster_snapshots", {}, "rds-snapshot-public", engine.PASS),
    ("describe_acm_certificates", {}, "acm-expiry", engine.PASS),
]


@pytest.mark.parametrize("collector, overrides, check_id, wrong_status", DENIED_CASES)
def test_a_denied_call_scores_its_check_as_no_data(collector, overrides, check_id, wrong_status):
    data = clean_bundle(**overrides)
    assert _status(data)[check_id] == wrong_status  # what the empty default alone says
    data[access.KEY] = [_denied(collector)]
    result = _result(data, check_id)
    assert result.status == engine.NO_DATA
    assert result.note == sc.DENIED_NOTE
    assert result.affected == []
    others = {cid: s for cid, s in _status(data).items() if s == engine.NO_DATA}
    assert set(others) <= {check_id, "rds-public", "rds-encryption", "guardduty-enabled"}


def test_denied_trails_and_account_block_public_access_are_no_data():
    data = clean_bundle()
    data["Global"]["CloudTrail"] = {"Trails": [], "HasMultiRegionTrail": False, "HasLoggingTrail": False, "HasLoggingMultiRegionTrail": False}
    data["Global"]["AccountPublicAccessBlock"] = None
    assert _status(data)["cloudtrail-multi-region"] == _status(data)["s3-account-bpa"] == engine.FAIL
    data[access.KEY] = [_denied("describe_trails"), _denied("account_public_access_block", "global")]
    statuses = _status(data)
    assert statuses["cloudtrail-multi-region"] == statuses["cloudtrail-log-validation"] == statuses["s3-account-bpa"] == engine.NO_DATA


def test_every_mapped_collector_exists_and_swallows_denials():
    from shared.awslib.collectors import cloudtrail, compute

    modules = (security, data_stores, compute, cloudtrail)
    for name in (*sc.DENIED_REGION_EVIDENCE, *sc.DENIED_GLOBAL_EVIDENCE):
        fn = next((getattr(m, name) for m in modules if hasattr(m, name)), None)
        assert fn is not None, f"{name} is mapped but no collector has that name"
        assert hasattr(fn, "__wrapped__"), f"{name} isn't wrapped in ignore_access_denied, so it can never be recorded"


def test_a_pass_needs_every_region_and_a_real_failure_survives_a_denial_elsewhere():
    data = clean_bundle()
    data["Regions"]["eu-west-1"] = copy.deepcopy(data["Regions"]["us-east-1"])
    data["Regions"]["eu-west-1"]["Security"]["GuardDuty"] = {"Enabled": False, "DetectorIds": []}
    data[access.KEY] = [_denied("guardduty_detector_ids", "eu-west-1")]
    # us-east-1 is on, eu-west-1 unread: not a PASS "in every scanned region".
    assert _result(data, "guardduty-enabled").status == engine.NO_DATA

    data["Regions"]["us-east-1"]["Security"]["GuardDuty"] = {"Enabled": False}
    result = _result(data, "guardduty-enabled")
    assert result.status == engine.FAIL
    assert [a.region for a in result.affected] == ["us-east-1"]  # the unread region is not accused
    assert result.note == sc.PARTIAL_NOTE


def test_a_region_without_an_analyzer_does_not_block_the_findings_check():
    data = clean_bundle()
    data["Regions"]["eu-west-1"] = copy.deepcopy(data["Regions"]["us-east-1"])
    data["Regions"]["eu-west-1"]["Security"]["AccessAnalyzers"] = []
    assert _status(data)["access-analyzer-findings"] == engine.PASS
    assert _status(data)["access-analyzer-enabled"] == engine.FAIL


def test_denials_do_not_invent_attack_paths_or_lower_detection_coverage():
    data = clean_bundle(
        GuardDuty={"Enabled": False, "DetectorIds": []},
        WideOpenSecurityGroups=[{"GroupId": "sg-1", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "OpenRanges": ["0.0.0.0/0"]}],
    )
    assert "exposure-without-detection" in {p.id for p in sc.attack_paths(data)}
    assert sc.detection_coverage(data) == (4, 5)
    data[access.KEY] = [_denied("guardduty_detector_ids")]
    assert "exposure-without-detection" not in {p.id for p in sc.attack_paths(data)}
    assert sc.detection_coverage(data) == (4, 4)


def test_denied_findings_raise_no_threats():
    data = clean_bundle(GuardDutyFindings=[{"Type": "Recon:EC2/Portscan", "Severity": 8}])
    assert len(sc.threats(data, security.guardduty_severity_label)) == 1
    data[access.KEY] = [_denied("guardduty_findings")]
    assert sc.threats(data, security.guardduty_severity_label) == []


def test_readable_evidence_leaves_the_original_untouched_and_is_a_no_op_without_denials():
    data = clean_bundle()
    assert sc.readable_evidence(data) is data
    data[access.KEY] = [_denied("guardduty_detector_ids"), _denied("unknown_collector"), _denied("macie_status", "ap-south-1")]
    readable = sc.readable_evidence(data)
    assert "GuardDuty" not in readable["Regions"]["us-east-1"]["Security"]
    assert "GuardDuty" in data["Regions"]["us-east-1"]["Security"]
    assert "Macie" in readable["Regions"]["us-east-1"]["Security"]  # denied in a region this run didn't scan


def test_unread_buckets_stop_a_pass_but_not_a_failure():
    data = clean_bundle()
    data["Global"]["DataStores"]["BucketsNotRead"] = [{"Name": "b", "Settings": ["PublicAccessBlock"]}]
    public = _result(data, "s3-bucket-public")
    assert public.status == engine.NO_DATA and public.note.startswith(sc.DENIED_NOTE) and "Buckets not read: 1" in public.note
    assert _status(data)["s3-default-encryption"] == engine.PASS  # that setting was readable

    data["Global"]["DataStores"]["PubliclyAccessibleBuckets"] = [{"Name": "open"}]
    public = _result(data, "s3-bucket-public")
    assert public.status == engine.FAIL and public.note.startswith(sc.PARTIAL_NOTE)
    assert "Account-level Block Public Access is fully on" in public.note  # both notes are kept

    data["Global"]["DataStores"]["BucketsNotRead"] = [{"Name": "b", "Settings": ["Encryption"]}]
    assert _status(data)["s3-default-encryption"] == engine.NO_DATA


# ------------------------------------------------------------------ DR checks
def _dr_status(data) -> dict:
    return {r.check.id: r.status for r in dr_checks.evaluate_checks(data)}


EMPTY_BACKUP = {"PlanCount": 0, "VaultCount": 0, "PlansWithCrossRegionCopy": 0, "ProtectedResourceCount": 0, "RecentFailedJobs": 0}


@pytest.mark.parametrize(
    "collector, check_id, overrides, wrong_status",
    [
        ("list_backup_plans", "dr-backup-plan", {"Backup": EMPTY_BACKUP}, engine.FAIL),
        ("list_protected_resources", "dr-backup-protected", {"Backup": EMPTY_BACKUP}, engine.FAIL),
        ("list_backup_plans", "dr-cross-region-copy", {"Backup": {**EMPTY_BACKUP, "PlanCount": 1}}, engine.FAIL),
        ("list_recent_jobs", "dr-backup-jobs", {}, engine.PASS),
        ("describe_rds_instances", "dr-rds-multi-az", {}, engine.PASS),
        ("describe_rds_clusters", "dr-rds-cluster-az", {}, engine.PASS),
        ("list_health_checks", "dr-health-checks", {"Route53HealthChecks": []}, engine.FAIL),
    ],
)
def test_a_denied_dr_call_is_no_data_with_a_note(collector, check_id, overrides, wrong_status):
    data = dr_bundle(**overrides)
    assert _dr_status(data)[check_id] == wrong_status
    data[access.KEY] = [_denied(collector)]
    result = next(r for r in dr_checks.evaluate_checks(data) if r.check.id == check_id)
    assert result.status == engine.NO_DATA and result.note == dr_checks.DENIED_NOTE


def test_dr_evidence_that_was_found_still_counts_despite_a_denial_elsewhere():
    data = dr_bundle(
        Backup={"PlanCount": 1, "PlansWithCrossRegionCopy": 1, "ProtectedResourceCount": 2, "RecentFailedJobs": 3},
        Rds={"SingleAzInstances": [{"DBInstanceIdentifier": "db"}], "SingleAzClusters": [{"DBClusterIdentifier": "c"}]},
    )
    data[access.KEY] = [
        _denied(c, "eu-west-1")
        for c in ("list_backup_plans", "list_protected_resources", "list_recent_jobs", "describe_rds_instances", "describe_rds_clusters", "list_health_checks")
    ]
    statuses = _dr_status(data)
    assert statuses["dr-backup-plan"] == statuses["dr-backup-protected"] == statuses["dr-cross-region-copy"] == engine.PASS
    assert statuses["dr-backup-jobs"] == statuses["dr-rds-multi-az"] == statuses["dr-rds-cluster-az"] == engine.FAIL
    assert statuses["dr-health-checks"] == engine.PASS


def test_dr_no_data_for_another_reason_carries_no_denial_note():
    data = dr_bundle()
    data["Global"]["Route53HostedZones"] = []
    result = next(r for r in dr_checks.evaluate_checks(data) if r.check.id == "dr-health-checks")
    assert result.status == engine.NO_DATA and result.note == ""


def test_every_dr_check_names_its_collectors():
    assert set(dr_checks.COLLECTORS) == {check.id for check, _ in dr_checks.CATALOG}


# --------------------------------------------------------------- the section
def test_access_gaps_section_groups_regions_and_names_resources():
    entries = [
        _denied("guardduty_detector_ids", "us-east-1", Operation="ListDetectors"),
        _denied("guardduty_detector_ids", "eu-west-1", Operation="ListDetectors"),
        *[_denied("list_buckets", "us-east-1", Operation="GetPublicAccessBlock", Resource=f"b{i}") for i in range(7)],
    ]
    report = Report(title="t")
    assert access.add_section(report, {access.KEY: entries}) is True
    section = report.sections[-1]
    assert section.title == access.SECTION_TITLE
    assert "| ListDetectors | guardduty detector ids | us-east-1, eu-west-1 | AccessDenied |" in section.body_md
    assert "us-east-1 (b0, b1, b2, b3, b4 and 2 more)" in section.body_md
    assert "PERMISSIONS.md" in section.body_md


def test_no_section_when_nothing_was_denied():
    report = Report(title="t")
    assert access.add_section(report, {"Regions": {}}) is False
    assert report.sections == []


def test_context_denied_list_is_per_context():
    a, b = AwsContext(region="us-east-1"), AwsContext(region="us-east-1")
    a.record_denied("c", "us-east-1", "AccessDenied", "Op")
    assert b.denied == []


# ----------------------------------------------------------------- the reports
from tests import test_skill_scripts as fixtures  # noqa: E402

security_scan = fixtures.security_scan
dr_readiness = fixtures.dr_readiness
collect_evidence = fixtures.collect_evidence


def test_security_report_scores_and_explains_a_denied_scan():
    data = fixtures._security_data(GuardDuty={"Enabled": False, "DetectorIds": []})
    data[access.KEY] = [
        {"Collector": "guardduty_detector_ids", "Operation": "ListDetectors", "Region": "us-east-1", "Code": "AccessDeniedException"},
        {"Collector": "unencrypted_ebs_volumes", "Operation": "DescribeVolumes", "Region": "us-east-1", "Code": "UnauthorizedOperation"},
    ]
    clean = security_scan.analyze(fixtures._security_data())
    analysis = security_scan.analyze(data)
    # Two checks drop out of the score instead of one failing and one passing.
    assert analysis["score"].no_data == clean["score"].no_data + 2
    assert analysis["score"].failed == clean["score"].failed
    assert not [a for a in analysis["actions"] if "GuardDuty" in a.action]

    report = security_scan.build_report(data, analysis)
    md = fixtures._assert_renders(report)
    assert "**The scan was denied 2 calls.** 2 checks could not be evaluated and are left out of the score." in md
    titles = [s.title for s in report.sections]
    assert titles.index(access.SECTION_TITLE) < titles.index("Detection Coverage")
    assert "| ListDetectors | guardduty detector ids | us-east-1 | AccessDeniedException |" in md
    coverage = next(s.body_md for s in report.sections if s.title == "Detection Coverage")
    assert "| us-east-1 | unknown | enabled |" in coverage
    assert sc.DENIED_NOTE in md
    kpis = {k.label: k for k in report.kpis}
    assert kpis["Detection coverage"].value == "100%"  # the unread service is not counted as off

    saved = security_scan.evidence_with_analysis(data, analysis)
    assert saved[access.KEY] == data[access.KEY]
    guardduty = next(c for c in saved["Analysis"]["Checks"] if c["Id"] == "guardduty-enabled")
    assert guardduty["Status"] == engine.NO_DATA and guardduty["Note"] == sc.DENIED_NOTE


def test_security_report_has_no_access_section_or_summary_line_when_nothing_was_denied():
    report = security_scan.build_report(fixtures._security_data())
    md = report.render_markdown()
    assert access.SECTION_TITLE not in [s.title for s in report.sections]
    assert "was denied" not in md


def test_security_summary_counts_one_denied_call_in_the_singular():
    data = fixtures._security_data()
    data[access.KEY] = [{"Collector": "securityhub_standards_summary", "Operation": "GetEnabledStandards", "Region": "us-east-1", "Code": "AccessDenied"}]
    md = security_scan.build_report(data).render_markdown()
    # No check reads that evidence, so the line names the denial and nothing more.
    assert "- **The scan was denied 1 call.** Access Gaps lists what to grant before the next run." in md

    data[access.KEY] = [{"Collector": "macie_status", "Operation": "GetMacieSession", "Region": "us-east-1", "Code": "AccessDeniedException"}]
    md = security_scan.build_report(data).render_markdown()
    assert "1 check could not be evaluated and is left out of the score." in md


def test_priority_list_is_only_called_the_top_ten_when_it_has_ten():
    few = security_scan.build_report(fixtures._security_data(GuardDuty={"Enabled": False})).render_markdown()
    assert "The fixes, most severe first" in few and "ten most important" not in few
    actions = [engine.Action(n, "LOW", "fix", "why", "account-wide", "--", "Low", "check") for n in range(1, 11)]
    assert "The ten most important fixes, most severe first" in security_scan._priority_actions(actions)


def _dr_report_data(**summary_overrides) -> dict:
    data = dr_bundle(**summary_overrides)
    data["Summary"]["Backup"].setdefault("VaultCount", 0)
    return data


def test_dr_report_does_not_call_unread_backup_evidence_a_gap():
    data = _dr_report_data(Backup=dict(EMPTY_BACKUP))
    plain = dr_readiness.build_report(data)
    assert {k.label: k for k in plain.kpis}["Backup plans"].tone == "bad"
    assert "lower bound" not in plain.render_markdown()

    data[access.KEY] = [
        {"Collector": c, "Operation": op, "Region": "us-east-1", "Code": "AccessDeniedException"}
        for c, op in (("list_backup_plans", "ListBackupPlans"), ("list_protected_resources", "ListProtectedResources"))
    ]
    report = dr_readiness.build_report(data)
    md = fixtures._assert_renders(report)
    kpis = {k.label: k for k in report.kpis}
    assert (kpis["Backup plans"].value, kpis["Backup plans"].note, kpis["Backup plans"].tone) == ("n/a", "access denied", "neutral")
    assert kpis["Protected resources"].value == "n/a"
    assert "these counts are a lower bound" in md
    assert f"- An AWS Backup plan exists: {dr_checks.DENIED_NOTE}" in md
    assert "No AWS Backup plan" not in md  # no "what to fix" row for a plan nobody could list
    assert [s.title for s in report.sections][:2] == ["Readiness Checks", access.SECTION_TITLE]


def test_dr_kpis_show_what_was_found_even_when_another_region_was_denied():
    data = _dr_report_data()
    data[access.KEY] = [{"Collector": "list_backup_plans", "Operation": "ListBackupPlans", "Region": "eu-west-1", "Code": "AccessDeniedException"}]
    kpis = {k.label: k for k in dr_readiness.build_report(data).kpis}
    assert kpis["Backup plans"].value == "1" and kpis["Backup plans"].tone == "good"


def test_well_architected_pack_carries_denials_into_its_security_checks():
    evidence = fixtures._wa_evidence()
    assert "| SEC04 | FAIL | HIGH | GuardDuty is enabled in every scanned region |" in collect_evidence._security_check_section(evidence)
    evidence[access.KEY] = [{"Collector": "guardduty_detector_ids", "Operation": "ListDetectors", "Region": "us-east-1", "Code": "AccessDeniedException"}]
    assert collect_evidence.security_bundle(evidence)[access.KEY] == evidence[access.KEY]
    section = collect_evidence._security_check_section(evidence)
    assert "| SEC04 | NO DATA | HIGH | GuardDuty is enabled in every scanned region |" in section
    assert f"_GuardDuty is enabled in every scanned region: {sc.DENIED_NOTE}_" in section


@pytest.mark.parametrize(
    "script, collect_args",
    [
        ("security_scan", (["us-east-1"],)),
        ("dr_readiness", (["us-east-1"],)),
        ("collect_evidence", (["us-east-1"], None)),
        ("discover", (["us-east-1"],)),
        ("analyze_cost", ("2024-01-01", "2024-03-01", ["us-east-1"])),
        ("traffic_analysis", ("us-east-1", "/vpc/fl", 6)),
    ],
)
def test_every_collect_saves_the_denied_calls_in_the_evidence(monkeypatch, script, collect_args):
    """Denials recorded while collecting must reach the evidence, or the
    checks and the report never learn about them."""
    from unittest.mock import MagicMock

    module = getattr(fixtures, script)
    entry = {"Collector": "x", "Operation": "Op", "Region": "us-east-1", "Code": "AccessDenied"}

    class Ctx:
        denied = [entry]

        def account_id(self):
            return "123456789012"

    for name in ("vpc", "compute", "containers", "data_stores", "security", "backup", "dr", "cloudtrail", "cost", "observability", "quotas", "well_architected", "nt"):
        if hasattr(module, name):
            monkeypatch.setattr(module, name, MagicMock())
    data = module.collect(Ctx(), *collect_args)
    assert data[access.KEY] == [entry]
    assert data[access.KEY] is not Ctx.denied


ONE_DENIAL = [{"Collector": "guardduty_findings", "Operation": "GetFindings", "Region": "us-east-1", "Code": "AccessDeniedException"}]


def test_traffic_report_lists_what_was_denied():
    data = {
        "Window": {"Start": "2024-01-01T00:00:00", "End": "2024-01-02T00:00:00"},
        "FlowLogAnalysis": {k: [] for k in ("top_talkers_by_bytes", "traffic_by_protocol", "rejected_traffic", "port_scan_candidates", "top_external_egress")},
        "NetworkFindings": [],
        access.KEY: ONE_DENIAL,
    }
    report = fixtures.traffic_analysis.build_report(data, "us-east-1", "/vpc/flowlogs")
    assert report.sections[-1].title == access.SECTION_TITLE
    assert "| GetFindings | guardduty findings | us-east-1 | AccessDeniedException |" in fixtures._assert_renders(report)


def test_well_architected_pack_lists_what_was_denied():
    evidence = {**fixtures._wa_evidence(), access.KEY: ONE_DENIAL}
    report = collect_evidence.build_report(evidence, ["security"])
    assert access.SECTION_TITLE in [s.title for s in report.sections]


@pytest.mark.parametrize("script", ["discover", "analyze_cost"])
def test_inventory_and_cost_reports_add_the_access_section(script):
    """These two need large fixtures to render; the wiring is one call, so
    it is pinned at the source instead."""
    import inspect

    assert "access.add_section(report, " in inspect.getsource(getattr(fixtures, script).build_report)


# ------------------------------------------------- one resource out of many
def test_a_kms_key_that_denies_the_scan_is_recorded_and_stops_a_pass(ctx):
    _, stub = install_stub(ctx, "kms", region="us-east-1")
    stub.add_response("list_keys", {"Keys": [{"KeyId": "k-denied"}, {"KeyId": "k-gone"}]}, {})
    stub.add_client_error("describe_key", service_error_code="AccessDeniedException")
    stub.add_client_error("describe_key", service_error_code="NotFoundException")
    assert security.kms_keys_without_rotation(ctx, "us-east-1") == []
    assert ctx.denied == [
        {"Collector": "kms_keys_without_rotation", "Operation": "DescribeKey", "Region": "us-east-1", "Code": "AccessDeniedException", "Resource": "k-denied"}
    ]

    data = clean_bundle()
    data[access.KEY] = list(ctx.denied)
    result = _result(data, "kms-rotation")
    assert result.status == engine.NO_DATA
    assert result.note == sc.DENIED_NOTE + " KMS keys not read: 1."
    # The rest of the region's evidence is intact: only the key was unread.
    assert "KmsKeysWithoutRotation" in sc.readable_evidence(data)["Regions"]["us-east-1"]["Security"]

    data["Regions"]["us-east-1"]["Security"]["KmsKeysWithoutRotation"] = [{"KeyId": "k-flag"}]
    result = _result(data, "kms-rotation")
    assert result.status == engine.FAIL and result.note == sc.PARTIAL_NOTE + " KMS keys not read: 1."


def test_a_key_unread_in_one_region_does_not_touch_another():
    data = clean_bundle()
    data["Regions"]["eu-west-1"] = copy.deepcopy(data["Regions"]["us-east-1"])
    data["Regions"]["eu-west-1"]["Security"]["KmsKeysWithoutRotation"] = [{"KeyId": "k-eu"}]
    data[access.KEY] = [_denied("kms_keys_without_rotation", "us-east-1", Resource="k-us")]
    result = _result(data, "kms-rotation")
    assert result.status == engine.FAIL and [a.region for a in result.affected] == ["eu-west-1"]


def test_a_failure_is_marked_partial_even_when_the_denied_region_added_nothing():
    """The unread region contributes no affected resources either way, so
    comparing counts can't see it; the note still has to be there."""
    data = clean_bundle(UnencryptedEbsVolumes=[{"VolumeId": "vol-1"}])
    data["Regions"]["eu-west-1"] = copy.deepcopy(clean_bundle()["Regions"]["us-east-1"])
    assert _result(data, "ebs-volume-encryption").note == ""
    data[access.KEY] = [_denied("unencrypted_ebs_volumes", "eu-west-1")]
    result = _result(data, "ebs-volume-encryption")
    assert result.status == engine.FAIL and len(result.affected) == 1
    assert result.note == sc.PARTIAL_NOTE
    untouched = [r for r in sc.evaluate_checks(data) if r.note and r.check.id != "ebs-volume-encryption"]
    assert untouched == []


def test_denied_account_wide_evidence_is_found_without_any_region():
    data = {"Regions": {}, "Global": {"AccountPublicAccessBlock": None}, access.KEY: [_denied("account_public_access_block", "global")]}
    result = _result(data, "s3-account-bpa")
    assert result.status == engine.NO_DATA and result.note == sc.DENIED_NOTE


# ------------------------------------------- evidence tables say "unknown"
def test_security_evidence_tables_show_unknown_not_zero_for_denied_evidence():
    data = fixtures._security_data()
    data["Global"]["CloudTrail"] = {"Trails": [], "HasMultiRegionTrail": False, "HasLoggingTrail": False, "HasLoggingMultiRegionTrail": False, "HasLogFileValidation": False}
    data["Global"]["AccountPublicAccessBlock"] = None
    data["Global"]["DataStores"]["BucketsNotRead"] = [{"Name": "locked", "Settings": ["PublicAccessBlock"]}]
    data[access.KEY] = [
        _denied("unencrypted_ebs_volumes"),
        _denied("guardduty_findings"),
        _denied("describe_trails"),
        _denied("account_public_access_block", "global"),
    ]
    report = security_scan.build_report(data)
    body = {s.title: s.body_md for s in report.sections}
    assert "| us-east-1 | on | unknown | 0 | 0 |" in body["Encryption Posture (EBS and KMS)"]
    assert "| us-east-1 | unknown | 0 | 0 |" in body["Threat Findings"]
    assert "Trails could not be listed" in body["CloudTrail"] and "NO -- gap" not in body["CloudTrail"]
    s3 = body["S3 Exposure"]
    assert "**Account-level S3 Block Public Access:** unknown" in s3
    assert "**Buckets the scan couldn't read:** 1" in s3
    assert "among those the scan could read" in s3
    fixtures._assert_renders(report)


def test_security_evidence_tables_are_unchanged_when_nothing_was_denied():
    data = fixtures._security_data()
    data["Global"]["AccountPublicAccessBlock"] = None
    body = {s.title: s.body_md for s in security_scan.build_report(data).sections}
    assert "| us-east-1 | on | 0 | 0 | 0 |" in body["Encryption Posture (EBS and KMS)"]
    assert "NOT configured -- gap" in body["S3 Exposure"]
    assert "No publicly-exposed or unencrypted S3 buckets detected." in body["S3 Exposure"]
    assert "Multi-region trail configured" in body["CloudTrail"]


# ------------------------------------------------------------ organizations
def test_organizations_report_lists_the_denied_call_behind_no_visibility():
    org = fixtures.analyze_organization
    posture = {"IsOrganizationsMember": False, access.KEY: [_denied("is_organizations_member", "global", Operation="DescribeOrganization")]}
    report = org.build_report(posture)
    assert report.sections[-1].title == access.SECTION_TITLE
    assert "DescribeOrganization" in report.render_markdown()
    assert access.SECTION_TITLE not in [s.title for s in org.build_report({"IsOrganizationsMember": False}).sections]


def test_organizations_report_lists_denied_calls_for_a_member_too():
    import inspect

    source = inspect.getsource(fixtures.analyze_organization.build_report)
    assert source.count("access.add_section(report, posture)") == 2  # the early return and the full report


# --------------------------------------------------------------- DR regions
@pytest.mark.parametrize(
    "db, region",
    [
        ({"DBInstanceArn": "arn:aws:rds:eu-west-1:123456789012:db:app"}, "eu-west-1"),
        ({"DBClusterArn": "arn:aws:rds:ap-south-1:123456789012:cluster:c"}, "ap-south-1"),
        ({"AvailabilityZone": "us-east-1a"}, "us-east-1"),
        ({"AvailabilityZones": ["us-west-2b", "us-west-2c"]}, "us-west-2"),
        ({"DBInstanceArn": "not-an-arn"}, "global"),
        ({}, "global"),
    ],
)
def test_dr_findings_name_the_region_the_database_is_in(db, region):
    assert dr_checks._region_of(db) == region


def test_single_az_databases_are_scoped_by_region():
    data = dr_bundle(
        Rds={
            "SingleAzInstances": [{"DBInstanceIdentifier": "db", "DBInstanceArn": "arn:aws:rds:eu-west-1:1:db:db"}],
            "SingleAzClusters": [{"DBClusterIdentifier": "c", "AvailabilityZones": ["us-east-1a"]}],
        }
    )
    results = {r.check.id: r for r in dr_checks.evaluate_checks(data)}
    assert engine.scope_text(results["dr-rds-multi-az"].affected) == "1 resource in eu-west-1"
    assert engine.scope_text(results["dr-rds-cluster-az"].affected) == "1 resource in us-east-1"


# --------------------------------------------------------- traffic analysis
def test_traffic_report_says_which_queries_did_not_finish():
    data = {
        "Window": {"Start": "2024-01-01T00:00:00", "End": "2024-01-02T00:00:00"},
        "FlowLogAnalysis": {
            **{k: [] for k in ("top_talkers_by_bytes", "traffic_by_protocol", "rejected_traffic", "port_scan_candidates", "top_external_egress")},
            "incomplete_queries": [{"Query": "rejected_traffic", "Status": "Timeout"}],
        },
        "NetworkFindings": [],
    }
    report = fixtures.traffic_analysis.build_report(data, "us-east-1", "/vpc/flowlogs")
    assert report.sections[0].title == "Incomplete Queries"
    md = fixtures._assert_renders(report)
    assert "| rejected traffic | Timeout |" in md and "not evidence of no traffic" in md
    data["FlowLogAnalysis"]["incomplete_queries"] = []
    assert "Incomplete Queries" not in [s.title for s in fixtures.traffic_analysis.build_report(data, "us-east-1", "/vpc/flowlogs").sections]


def test_traffic_scan_stops_with_one_line_when_the_log_group_is_missing(monkeypatch, capsys, tmp_path):
    traffic = fixtures.traffic_analysis

    def missing(*args, **kwargs):
        _raise("ResourceNotFoundException", "StartQuery")

    monkeypatch.setattr(traffic, "collect", missing)
    code = traffic.main(["--region", "eu-west-1", "--log-group", "/vpc/nope", "--output-dir", str(tmp_path)])
    assert code == 2
    assert "log group '/vpc/nope' was not found in eu-west-1" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []

    def throttled(*args, **kwargs):
        _raise("ThrottlingException", "StartQuery")

    monkeypatch.setattr(traffic, "collect", throttled)
    with pytest.raises(ClientError):
        traffic.main(["--region", "eu-west-1", "--log-group", "/vpc/nope", "--output-dir", str(tmp_path)])


# ------------------------------------------------- a scan that can't proceed
def test_run_turns_a_denied_core_call_into_one_clear_line(capsys):
    from shared.awslib.cli import run

    def main(argv=None):
        _raise("UnauthorizedOperation", "DescribeSecurityGroups", "You are not authorized to perform: ec2:DescribeSecurityGroups")

    assert run(main) == 2
    err = capsys.readouterr().err
    assert "the scan needs DescribeSecurityGroups and was denied (UnauthorizedOperation)" in err
    assert "ec2:DescribeSecurityGroups" in err and "PERMISSIONS.md" in err
    assert "Traceback" not in err


def test_run_explains_unusable_credentials(capsys):
    from botocore.exceptions import NoCredentialsError, ProfileNotFound

    from shared.awslib.cli import run

    def no_credentials(argv=None):
        raise NoCredentialsError()

    def no_profile(argv=None):
        raise ProfileNotFound(profile="nope")

    assert run(no_credentials) == 2
    assert "NoCredentialsError" in capsys.readouterr().err
    assert run(no_profile) == 2
    err = capsys.readouterr().err
    assert "ProfileNotFound" in err and "nope" in err and "--profile" in err


def test_run_passes_results_through_and_lets_real_errors_raise():
    from shared.awslib.cli import run

    assert run(lambda argv=None: 0) == 0
    assert run(lambda argv=None: argv, ["--x"]) == ["--x"]

    def throttled(argv=None):
        _raise("ThrottlingException")

    with pytest.raises(ClientError):
        run(throttled)
    with pytest.raises(ZeroDivisionError):
        run(lambda argv=None: 1 / 0)


def test_run_reports_a_denial_without_a_message(capsys):
    from shared.awslib.cli import run

    def main(argv=None):
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListUsers")

    assert run(main) == 2
    assert "No further detail from AWS." in capsys.readouterr().err


def test_every_script_enters_through_run():
    from pathlib import Path

    scripts = sorted((Path(__file__).resolve().parents[1] / "skills").glob("*/scripts/*.py"))
    assert len(scripts) == 7
    for script in scripts:
        assert "raise SystemExit(run(main))" in script.read_text(), script.name


# ------------------------------------------------------ IAM credential report
def test_credential_report_waits_past_ten_seconds_for_a_large_account(ctx, monkeypatch):
    waits = []
    monkeypatch.setattr(security.time, "sleep", waits.append)
    _, stub = install_stub(ctx, "iam")
    for _ in range(12):
        stub.add_response("generate_credential_report", {"State": "INPROGRESS"})
    stub.add_response("generate_credential_report", {"State": "COMPLETE"})
    stub.add_response("get_credential_report", {"Content": b"user,mfa_active\nalice,true\n", "ReportFormat": "text/csv"})
    assert security.iam_credential_report(ctx) == [{"user": "alice", "mfa_active": "true"}]
    assert len(waits) == 12 and sum(waits) > 10
    assert security.CREDENTIAL_REPORT_ATTEMPTS * security.CREDENTIAL_REPORT_WAIT_SECONDS == 60
