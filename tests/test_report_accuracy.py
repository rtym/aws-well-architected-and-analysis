"""Reports say only what the scan read.

A review of 1.7.0 found places where a report still stated something the
scan never saw: an empty default from a denied call printed as "nothing
there", a wrong quota code printed under another quota's name, a region
the user didn't ask for. Others crashed on a documented command. Each test
here pins one of those fixes.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from shared.analysis import access, dr_checks
from shared.analysis import checks as engine
from shared.analysis import security_checks as sc
from shared.awslib import cli
from shared.awslib.collectors import backup, cloudtrail, dr, network_traffic, quotas, security
from shared.awslib.session import AwsContext, ScanStopped
from shared.reporting import jsonutil
from tests import test_skill_scripts as fixtures
from tests.stub_helpers import install_stub
from tests.test_analysis_dr_checks import dr_bundle

discover = fixtures.discover
dr_readiness = fixtures.dr_readiness
analyze_cost = fixtures.analyze_cost
traffic_analysis = fixtures.traffic_analysis
collect_evidence = fixtures.collect_evidence
analyze_organization = fixtures.analyze_organization
security_scan = fixtures.security_scan


def _denied(collector: str, operation: str = "Op", region: str = "us-east-1", **extra) -> dict:
    return {"Collector": collector, "Operation": operation, "Region": region, "Code": "AccessDeniedException", **extra}


class _Stop(Exception):
    pass


# ------------------------------------------------------------ --json-out
def test_json_out_creates_its_folder(tmp_path):
    """Every SKILL.md passes `--json-out reports/output/...`, and the scripts
    write the JSON before the report creates --output-dir: a first run
    failed with FileNotFoundError after the whole scan."""
    path = tmp_path / "reports" / "output" / "evidence.json"
    jsonutil.write({"a": 1}, str(path))
    assert path.read_text().strip().startswith("{")


def test_json_out_into_a_new_folder_runs_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(analyze_organization, "collect", lambda *a, **k: {"IsOrganizationsMember": False, access.KEY: []})
    code = analyze_organization.main(["--region", "us-east-1", "--formats", "md", "--json-out", "reports/output/org.json"])
    assert code == 0
    assert (tmp_path / "reports" / "output" / "org.json").exists()


# ---------------------------------------------------------------- quotas
def test_quota_codes_match_their_labels():
    """L-DF5E4CA3 is "Network interfaces per Region" (default 5,000), and
    the report printed its value as "Rules per security group". L-0263D0A3
    is an EC2 quota, so asking for it under "vpc" returned nothing and the
    row disappeared. Codes from the AWS General Reference quota tables."""
    expected = {
        ("ec2", "L-1216C47A"): "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances",
        ("vpc", "L-F678F1CE"): "VPCs per Region",
        ("vpc", "L-E79EC296"): "VPC security groups per Region",
        ("vpc", "L-0EA8095F"): "Inbound or outbound rules per security group",
        ("vpc", "L-DF5E4CA3"): "Network interfaces per Region",
        ("elasticloadbalancing", "L-53DA6B97"): "Application Load Balancers per Region",
        ("rds", "L-7B6409FD"): "DB instances",
        ("lambda", "L-B99A9384"): "Concurrent executions",
    }
    assert {(svc, code): label for svc, code, label in quotas.COMMON_QUOTAS} == expected


# ----------------------------------------------------------------- region
def test_home_region_prefers_the_flag_then_the_profile_then_us_east_1(monkeypatch, tmp_path):
    assert AwsContext(region="ap-south-1").home_region() == "ap-south-1"
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    assert AwsContext().home_region() == "eu-west-1"
    monkeypatch.delenv("AWS_DEFAULT_REGION")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    assert AwsContext().home_region() == "us-east-1"


def test_account_block_public_access_client_has_a_region(monkeypatch, tmp_path):
    """With no --region and no region in the profile, the s3control client
    raised NoRegionError, and the security scan stopped at its last step."""
    monkeypatch.delenv("AWS_DEFAULT_REGION")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    ctx = AwsContext()
    s3control, stub = install_stub(ctx, "s3control", region="us-east-1")
    stub.add_response(
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}},
        {"AccountId": "123456789012"},
    )
    ctx._account_id = "123456789012"
    assert security.account_public_access_block(ctx) == {"BlockPublicAcls": True}


def test_enabled_regions_are_listed_from_the_profile_region(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    ctx = AwsContext()
    ec2, stub = install_stub(ctx, "ec2", region="eu-west-1")
    stub.add_response("describe_regions", {"Regions": [{"RegionName": "eu-west-1"}]}, {"AllRegions": False})
    assert ctx.enabled_regions() == ["eu-west-1"]


def test_cost_and_organizations_use_the_profile_region(monkeypatch):
    """Both fell back to us-east-1 even when the profile named another
    region, so idle resources and Compute Optimizer were read from a region
    the user didn't choose. The security scan already used the profile's."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    seen = {}

    def cost_collect(ctx, start, end, co_regions):
        seen["cost"] = co_regions
        raise _Stop

    def org_collect(ctx, home_region):
        seen["org"] = home_region
        raise _Stop

    monkeypatch.setattr(analyze_cost, "collect", cost_collect)
    monkeypatch.setattr(analyze_organization, "collect", org_collect)
    for module in (analyze_cost, analyze_organization):
        with pytest.raises(_Stop):
            module.main(["--formats", "md"])
    assert seen == {"cost": ["eu-west-1"], "org": "eu-west-1"}


def test_scan_stopped_is_one_line_and_exit_code_2(capsys):
    def main(argv=None):
        raise ScanStopped("the thing is not ready")

    assert cli.run(main) == 2
    assert capsys.readouterr().err.strip() == "Stopped: the thing is not ready"


def test_credential_report_that_never_finishes_stops_the_scan_cleanly(ctx, monkeypatch, capsys):
    monkeypatch.setattr(security, "CREDENTIAL_REPORT_ATTEMPTS", 2)
    monkeypatch.setattr(security.time, "sleep", lambda s: None)
    iam, stub = install_stub(ctx, "iam")
    for _ in range(2):
        stub.add_response("generate_credential_report", {"State": "STARTED"})
    assert cli.run(lambda argv=None: security.iam_credential_report(ctx)) == 2
    assert "still generating the credential report after 4 seconds" in capsys.readouterr().err
    stub.assert_no_pending_responses()


# -------------------------------------------------------------- CloudTrail
TRAIL = "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"
OTHER = "arn:aws:cloudtrail:us-east-1:123456789012:trail/other"


def _posture_with_denied_status(ctx, *, also=None):
    """CloudTrail posture where GetTrailStatus on the multi-region trail is
    denied; `also` adds a second trail with its own status."""
    ct, stub = install_stub(ctx, "cloudtrail", region="us-east-1")
    trails = [{"Name": "main", "TrailARN": TRAIL, "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]
    if also:
        trails.append({"Name": "other", "TrailARN": OTHER, **also["trail"]})
    stub.add_response("describe_trails", {"trailList": trails}, {"includeShadowTrails": True})
    stub.add_client_error("get_trail_status", service_error_code="AccessDeniedException")
    stub.add_client_error("get_event_selectors", service_error_code="AccessDeniedException")
    if also:
        stub.add_response("get_trail_status", also["status"], {"Name": OTHER})
        stub.add_response("get_event_selectors", {"EventSelectors": []}, {"TrailName": OTHER})
    return cloudtrail.cloudtrail_posture(ctx, "us-east-1")


def _ct_bundle(ctx, posture) -> dict:
    data = fixtures._security_data()
    data["Global"]["CloudTrail"] = posture
    data[access.KEY] = access.denied_calls(ctx)
    return data


def test_a_denied_trail_status_is_recorded_against_the_trail(ctx):
    """The status call went through a bare client with nothing to record
    the denial on: the trail read as "not logging" and Access Gaps was empty."""
    posture = _posture_with_denied_status(ctx)
    trail = posture["Trails"][0]
    assert trail["_StatusNotRead"] is True and trail["_Status"] is None and trail["_EventSelectors"] == []
    assert posture["TrailStatusNotRead"] == [TRAIL]
    assert [(d["Operation"], d["Resource"]) for d in ctx.denied] == [("GetTrailStatus", TRAIL), ("GetEventSelectors", TRAIL)]


def test_a_denied_trail_status_scores_cloudtrail_as_no_data(ctx):
    result = {r.check.id: r for r in sc.evaluate_checks(_ct_bundle(ctx, _posture_with_denied_status(ctx)))}["cloudtrail-multi-region"]
    assert result.status == engine.NO_DATA
    assert result.note == f"{sc.DENIED_NOTE} Trails not read: 1."


def test_another_logging_multi_region_trail_still_passes(ctx):
    posture = _posture_with_denied_status(ctx, also={"trail": {"IsMultiRegionTrail": True}, "status": {"IsLogging": True}})
    result = {r.check.id: r for r in sc.evaluate_checks(_ct_bundle(ctx, posture))}["cloudtrail-multi-region"]
    assert (result.status, result.note) == (engine.PASS, "")


def test_an_unread_single_region_trail_does_not_hide_a_failure(ctx):
    """Only a multi-region trail could satisfy CloudTrail.1, so an unread
    single-region trail leaves the failure standing."""
    ct, stub = install_stub(ctx, "cloudtrail", region="us-east-1")
    stub.add_response(
        "describe_trails", {"trailList": [{"Name": "single", "TrailARN": TRAIL, "IsMultiRegionTrail": False}]}, {"includeShadowTrails": True}
    )
    stub.add_client_error("get_trail_status", service_error_code="AccessDenied")
    stub.add_response("get_event_selectors", {"EventSelectors": []}, {"TrailName": TRAIL})
    posture = cloudtrail.cloudtrail_posture(ctx, "us-east-1")
    result = {r.check.id: r for r in sc.evaluate_checks(_ct_bundle(ctx, posture))}["cloudtrail-multi-region"]
    assert result.status == engine.FAIL


def test_security_report_says_unknown_for_an_unread_trail_status(ctx):
    md = security_scan.build_report(_ct_bundle(ctx, _posture_with_denied_status(ctx))).render_markdown()
    section = md.split("### CloudTrail", 1)[1].split("###", 1)[0]
    assert "- **A trail is actively logging:** unknown (the scan was denied the status of 1 trail; see Access Gaps)" in section
    assert "- **A multi-region trail is logging (CloudTrail.1):** unknown" in section
    assert "NO -- gap" not in section
    assert "| GetTrailStatus | describe trails | us-east-1 (" + TRAIL + ") | AccessDeniedException |" in md


def test_well_architected_pack_flags_an_unread_trail_status(ctx):
    evidence = {**fixtures._wa_evidence(), access.KEY: []}
    evidence["Global"]["CloudTrail"] = _posture_with_denied_status(ctx)
    md = collect_evidence.build_report(evidence, ["security"]).render_markdown()
    assert '- Trails whose status the run was denied: 1, so "False" above may be unknown (see Access Gaps)' in md


# ---------------------------------------------------------- Organizations
MEMBER_VIEW = {
    "IsOrganizationsMember": True,
    "Organization": {"MasterAccountId": "111111111111", "FeatureSet": "ALL"},
    "Accounts": [],
    "ServiceControlPolicies": [],
    "AccountsWithoutScpCoverage": [],
    "DelegatedAdministrators": [],
    "GuardDutyOrganizationAdmin": None,
    "SecurityHubOrganizationAdmin": None,
    access.KEY: [
        _denied("list_accounts", "ListAccounts", "global"),
        _denied("list_service_control_policies", "ListPolicies", "global"),
        _denied("list_delegated_administrators", "ListDelegatedAdministrators", "global"),
        _denied("guardduty_organization_admin", "ListOrganizationAdminAccounts"),
        _denied("securityhub_organization_admin", "ListOrganizationAdminAccounts"),
    ],
}


def test_org_report_from_a_member_account_claims_nothing_it_could_not_read():
    """A member account may describe its organization but not list its
    accounts or policies. The report said "Every member account has at
    least one restrictive SCP in effect" from zero accounts read."""
    report = analyze_organization.build_report(MEMBER_VIEW)
    md = fixtures._assert_renders(report)
    for claim in (
        "Every member account has at least one restrictive SCP",
        "No delegated administrator accounts registered",
        "NOT configured",
        "**Accounts:** 0",
    ):
        assert claim not in md
    assert "Not evaluated: the scan was denied the account or policy listing it needs" in md
    assert f"- **GuardDuty delegated administrator:** {analyze_organization.NOT_READ}" in md
    assert f"Delegated administrators: {analyze_organization.NOT_READ}." in md
    kpis = {k.label: (k.value, k.note) for k in report.kpis}
    for label in ("Accounts", "SCP coverage", "Restrictive SCPs", "Delegated admins", "GuardDuty org-managed", "Security Hub org-managed"):
        assert kpis[label] == ("n/a", "access denied"), label


def test_org_report_says_an_unread_ou_may_hide_coverage():
    posture = {
        **MEMBER_VIEW,
        "Accounts": [{"Id": "111111111111", "Name": "mgmt"}, {"Id": "222222222222", "Name": "prod"}],
        "ServiceControlPolicies": [{"Id": "p-1", "Name": "deny", "_Targets": [{"TargetId": "ou-1", "Type": "ORGANIZATIONAL_UNIT"}]}],
        "AccountsWithoutScpCoverage": [{"Id": "222222222222", "Name": "prod"}],
        access.KEY: [_denied("ou_descendant_account_ids", "ListAccountsForParent", "global")],
    }
    report = analyze_organization.build_report(posture)
    md = report.render_markdown()
    assert "an account below may be covered by an SCP attached to one of those OUs" in md
    coverage = {k.label: k for k in report.kpis}["SCP coverage"]
    assert (coverage.value, coverage.note, coverage.tone) == ("0%", "0 of 1 member accounts, at least: some OUs unread", "warn")


def test_org_report_still_reports_a_real_gap():
    posture = {**MEMBER_VIEW, access.KEY: []}
    md = analyze_organization.build_report(posture).render_markdown()
    assert "NOT configured -- each account manages GuardDuty independently" in md
    assert "No delegated administrator accounts registered" in md


# ----------------------------------------------- Well-Architected evidence
def test_workload_that_could_not_be_read_does_not_crash_the_report():
    evidence = {**fixtures._wa_evidence(), access.KEY: [_denied("get_workload", "GetWorkload")]}
    evidence["Workload"] = {"Workload": None, "Answers": [], "ImprovementsByPillar": {}}
    md = collect_evidence.build_report(evidence, ["security"]).render_markdown()
    assert "The workload couldn't be read: the run was denied the Well-Architected Tool calls" in md


@pytest.mark.parametrize("code", ["ResourceNotFoundException", "ValidationException"])
def test_wrong_workload_id_stops_before_the_long_collection(monkeypatch, capsys, code):
    def missing(ctx, region, workload_id):
        raise ClientError({"Error": {"Code": code, "Message": "no"}}, "GetWorkload")

    def must_not_run(*a, **k):
        raise AssertionError("collected before checking the workload")

    monkeypatch.setattr(collect_evidence.well_architected, "collect_workload_snapshot", missing)
    monkeypatch.setattr(collect_evidence.vpc, "collect_region_network", must_not_run)
    exit_code = cli.run(collect_evidence.main, ["--region", "eu-west-1", "--workload-id", "abc", "--formats", "md"])
    assert exit_code == 2
    assert "Well-Architected Tool workload 'abc' was not found in eu-west-1." in capsys.readouterr().err


def test_other_workload_errors_still_raise(monkeypatch):
    def throttled(ctx, region, workload_id):
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow"}}, "GetWorkload")

    monkeypatch.setattr(collect_evidence.well_architected, "collect_workload_snapshot", throttled)
    with pytest.raises(ClientError):
        collect_evidence._workload_snapshot(AwsContext(region="us-east-1"), "us-east-1", "abc")


def test_cost_explorer_denial_costs_the_pack_its_cost_evidence_only(ctx):
    """Cost Explorer is often closed to member accounts, and a denial there
    stopped the evidence pack for all six pillars."""
    ce, ce_stub = install_stub(ctx, "ce", region="us-east-1")
    ce_stub.add_client_error("get_cost_and_usage", service_error_code="AccessDeniedException")
    budgets, b_stub = install_stub(ctx, "budgets", region="us-east-1")
    b_stub.add_response("describe_budgets", {"Budgets": [{"BudgetName": "monthly", "TimeUnit": "MONTHLY", "BudgetType": "COST"}]})
    ctx._account_id = "123456789012"

    cost = collect_evidence._cost_evidence(ctx)
    assert [b["BudgetName"] for b in cost["Budgets"]] == ["monthly"]
    assert ctx.denied == [{"Collector": "collect_cost_report", "Operation": "GetCostAndUsage", "Region": "global", "Code": "AccessDeniedException"}]


def test_other_cost_explorer_errors_still_raise(ctx):
    ce, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_cost_and_usage", service_error_code="LimitExceededException")
    with pytest.raises(ClientError):
        collect_evidence._cost_evidence(ctx)


def test_well_architected_pack_says_unknown_for_denied_security_services():
    """The pack printed "GuardDuty enabled: False" from the collector's
    empty default when ListDetectors was denied."""
    evidence = fixtures._wa_evidence()
    evidence[access.KEY] = [
        _denied("guardduty_detector_ids", "ListDetectors"),
        _denied("securityhub_status", "DescribeHub"),
        _denied("access_analyzer_findings", "ListFindingsV2"),
    ]
    md = collect_evidence.build_report(evidence, ["security"]).render_markdown()
    for line in ("GuardDuty enabled", "Security Hub enabled", "IAM Access Analyzer active findings"):
        assert f"- {line}: unknown (access denied; see Access Gaps)" in md
    clean = collect_evidence.build_report(fixtures._wa_evidence(), ["security"]).render_markdown()
    assert "- GuardDuty enabled: False" in clean and "- IAM Access Analyzer active findings: 0" in clean


# ----------------------------------------------------------------- traffic
QUERY_KEYS = ("top_talkers_by_bytes", "traffic_by_protocol", "rejected_traffic", "distinct_dst_ports_per_src", "top_external_egress")


def _traffic(status: str, denied=()) -> dict:
    flow = {k: [] for k in QUERY_KEYS}
    flow["port_scan_candidates"] = []
    flow["incomplete_queries"] = [] if status in ("Complete", "Denied") else [{"Query": k, "Status": status} for k in QUERY_KEYS]
    flow["query_status"] = {k: status for k in QUERY_KEYS}
    return {
        "Window": {"Start": "2026-11-19T00:00:00", "End": "2026-11-20T00:00:00"},
        "FlowLogAnalysis": flow,
        "NetworkFindings": [],
        access.KEY: list(denied),
    }


def test_traffic_report_does_not_read_denied_queries_as_quiet_traffic():
    data = _traffic("Denied", [_denied("query_with_status", "StartQuery"), _denied("guardduty_detector_ids", "ListDetectors")])
    report = traffic_analysis.build_report(data, "us-east-1", "/vpc/flow")
    md = fixtures._assert_renders(report)
    for quiet in ("No flow log records", "No rejected flows", "No source exceeded", "No external egress", "No active Recon"):
        assert quiet not in md
    assert md.count("Not read: the scan was denied the Logs Insights query (see Access Gaps).") == 5
    assert "Not read: the scan was denied the GuardDuty calls (see Access Gaps)." in md
    kpis = {k.label: (k.value, k.note, k.tone) for k in report.kpis}
    for label in ("Traffic observed", "Rejected flows", "Port-scan suspects", "External destinations"):
        assert kpis[label] == ("n/a", "denied", "neutral"), label
    assert kpis["GuardDuty network findings"] == ("n/a", "access denied", "neutral")


def test_traffic_report_names_the_status_of_an_unfinished_query():
    report = traffic_analysis.build_report(_traffic("Timeout"), "us-east-1", "/vpc/flow")
    md = report.render_markdown()
    assert md.count("Not read: the query ended with status Timeout (see Incomplete Queries).") == 5
    assert {k.label: k.note for k in report.kpis}["Rejected flows"] == "query did not finish"


def test_traffic_report_still_says_quiet_when_the_queries_completed():
    report = traffic_analysis.build_report(_traffic("Complete"), "us-east-1", "/vpc/flow")
    md = report.render_markdown()
    assert "No rejected flows in this window." in md and "No active Recon" in md
    kpis = {k.label: (k.value, k.tone) for k in report.kpis}
    assert kpis["Rejected flows"] == ("0", "good") and kpis["GuardDuty network findings"] == ("0", "good")


def test_flow_log_analysis_records_every_query_status(ctx, monkeypatch):
    statuses = iter(["Complete", "Denied", "Timeout", "Complete", "Complete"])
    monkeypatch.setattr(network_traffic, "query_with_status", lambda *a, **k: ([], next(statuses)))
    result = network_traffic.analyze_flow_logs(ctx, "us-east-1", "/vpc/flow", 0, 1)
    assert list(result["query_status"].values()) == ["Complete", "Denied", "Timeout", "Complete", "Complete"]
    assert result["incomplete_queries"] == [{"Query": list(network_traffic.QUERIES)[2], "Status": "Timeout"}]


def test_a_query_still_running_at_the_local_timeout_is_stopped(ctx, monkeypatch):
    """Left running, it kept scanning (and billing) after the scan moved on."""
    monkeypatch.setattr(network_traffic.time, "sleep", lambda s: None)
    logs, stub = install_stub(ctx, "logs", region="us-east-1")
    stub.add_response("start_query", {"queryId": "q-1"})
    stub.add_response("get_query_results", {"status": "Running", "results": []}, {"queryId": "q-1"})
    stub.add_response("stop_query", {"success": True}, {"queryId": "q-1"})
    assert network_traffic.query_with_status(ctx, "us-east-1", "/vpc/flow", "q", 0, 1, timeout_s=2) == ([], "Running")
    stub.assert_no_pending_responses()


def test_a_failed_stop_does_not_lose_the_rows(ctx, monkeypatch):
    monkeypatch.setattr(network_traffic.time, "sleep", lambda s: None)
    logs, stub = install_stub(ctx, "logs", region="us-east-1")
    stub.add_response("start_query", {"queryId": "q-1"})
    stub.add_response("get_query_results", {"status": "Running", "results": [[{"field": "srcAddr", "value": "10.0.0.1"}]]})
    stub.add_client_error("stop_query", service_error_code="InvalidParameterException")
    rows, status = network_traffic.query_with_status(ctx, "us-east-1", "/vpc/flow", "q", 0, 1, timeout_s=2)
    assert (rows, status) == ([{"srcAddr": "10.0.0.1"}], "Running")


# ---------------------------------------------------------------------- DR
def _dr_data(instances=(), clusters=(), buckets=(), plans=(), denied=()) -> dict:
    regions = {
        "eu-west-1": {
            "Backup": {
                "BackupPlans": list(plans),
                "BackupVaults": [],
                "ProtectedResources": [],
                "FailedJobsRecent": [],
                "PlansWithCrossRegionCopy": backup.plans_with_cross_region_copy(list(plans), "eu-west-1"),
            },
            "DataStores": {"RdsInstances": list(instances), "RdsClusters": list(clusters)},
        }
    }
    data = {"Regions": regions, "Global": {"DataStores": {"S3Buckets": list(buckets)}, "Route53HealthChecks": [], "Route53HostedZones": []}}
    data["Summary"] = dr.dr_readiness_summary(dr_readiness._merge_backup(regions), list(instances), list(clusters), list(buckets), [])
    data[access.KEY] = list(denied)
    return data


MULTI_AZ = {"DBInstanceIdentifier": "prod", "MultiAZ": True, "Engine": "postgres"}


def test_dr_report_does_not_say_no_rds_when_every_database_is_multi_az():
    report = dr_readiness.build_report(_dr_data([MULTI_AZ]))
    md = fixtures._assert_renders(report)
    assert "No RDS instances found" not in md
    assert "1 standalone instance(s) and 0 cluster(s) found. Every one spans more than one Availability Zone" in md
    tile = {k.label: (k.value, k.note) for k in report.kpis}["Single-AZ databases"]
    assert tile == ("0", "of 1 standalone instance(s) and 0 cluster(s)")


def test_dr_report_mentions_a_partial_rds_denial():
    data = _dr_data([MULTI_AZ], denied=[_denied("describe_rds_clusters", "DescribeDBClusters", "eu-west-1")])
    assert "The scan was denied part of the RDS evidence (see Access Gaps)." in dr_readiness.build_report(data).render_markdown()


def test_dr_report_says_unread_when_rds_was_denied():
    data = _dr_data(denied=[_denied("describe_rds_instances", "DescribeDBInstances", "eu-west-1")])
    md = dr_readiness.build_report(data).render_markdown()
    assert "Not read: the scan was denied the RDS calls (see Access Gaps)." in md
    assert "No RDS instances found" not in md
    assert "No RDS instances found" in dr_readiness.build_report(_dr_data()).render_markdown()


def _plan(destination_region: str) -> dict:
    vault = f"arn:aws:backup:{destination_region}:123456789012:backup-vault:copy"
    return {"BackupPlanId": "p1", "BackupPlanName": "daily", "_Rules": [{"RuleName": "r", "CopyActions": [{"DestinationBackupVaultArn": vault}]}]}


def test_a_copy_into_the_same_region_is_not_cross_region():
    """Any copy rule passed "a backup plan copies recovery points to another
    region", including a copy to another vault in the plan's own region."""
    assert backup.plans_with_cross_region_copy([_plan("eu-west-1")], "eu-west-1") == []
    assert [p["BackupPlanId"] for p in backup.plans_with_cross_region_copy([_plan("eu-central-1")], "eu-west-1")] == ["p1"]
    statuses = {r.check.id: r.status for r in dr_checks.evaluate_checks(_dr_data([MULTI_AZ], plans=[_plan("eu-west-1")]))}
    assert statuses["dr-cross-region-copy"] == engine.FAIL


def test_only_cross_region_rules_are_kept_on_a_matching_plan():
    plan = _plan("eu-central-1")
    plan["_Rules"].append({"RuleName": "local", "CopyActions": [{"DestinationBackupVaultArn": "arn:aws:backup:eu-west-1:1:backup-vault:v"}]})
    plan["_Rules"].append({"RuleName": "unparsable", "CopyActions": [{"DestinationBackupVaultArn": "not-an-arn"}]})
    [match] = backup.plans_with_cross_region_copy([plan], "eu-west-1")
    assert [r["RuleName"] for r in match["Rules"]] == ["r"]


def test_unreadable_replication_is_neither_replicated_nor_not():
    buckets = [
        {"Name": "replicated", "_Replication": {"Role": "r"}},
        {"Name": "local", "_Replication": None},
        {"Name": "locked", "_Replication": None, "_Unreadable": ["Replication"]},
    ]
    signals = dr.s3_replication_signals(buckets)
    assert [[b["Name"] for b in signals[k]] for k in ("ReplicatedBuckets", "UnreplicatedBuckets", "ReplicationNotRead")] == [
        ["replicated"],
        ["local"],
        ["locked"],
    ]
    report = dr_readiness.build_report(_dr_data([MULTI_AZ], buckets=buckets))
    assert {k.label: (k.value, k.note) for k in report.kpis}["S3 replication"] == ("1/2", "buckets replicating; 1 not read")
    assert "The scan was denied the replication setting of **1** more (see Access Gaps); they are in neither count." in report.render_markdown()


def test_an_aurora_only_account_has_no_standalone_instance_to_judge():
    member = {"DBInstanceIdentifier": "aurora-1", "DBClusterIdentifier": "aurora", "MultiAZ": False}
    cluster = {"DBClusterIdentifier": "aurora", "MultiAZ": True}
    statuses = {r.check.id: r.status for r in dr_checks.evaluate_checks(_dr_data([member], [cluster]))}
    assert statuses["dr-rds-multi-az"] == engine.NO_DATA
    assert statuses["dr-rds-cluster-az"] == engine.PASS
    assert dr_checks.standalone_instance_count(dr_bundle()) == 1


def test_failed_jobs_tile_is_unknown_when_the_job_list_was_denied():
    data = _dr_data([MULTI_AZ], denied=[_denied("list_recent_jobs", "ListBackupJobs", "eu-west-1")])
    tile = {k.label: (k.value, k.note) for k in dr_readiness.build_report(data).kpis}["Failed backup jobs"]
    assert tile == ("n/a", "access denied")


def test_dr_scan_reads_only_the_rds_evidence_it_uses(ctx, monkeypatch):
    """The full data-store inventory also listed DynamoDB, ElastiCache, and
    Lambda, which no DR check reads; a denied DynamoDB call stopped the scan."""
    for name in ("list_dynamodb_tables", "describe_elasticache_clusters", "list_lambda_functions"):
        monkeypatch.setattr(dr_readiness.data_stores, name, lambda *a, **k: pytest.fail("DR scan read unused inventory"))
    monkeypatch.setattr(dr_readiness.data_stores, "describe_rds_instances", lambda ctx, region: [MULTI_AZ])
    monkeypatch.setattr(dr_readiness.data_stores, "describe_rds_clusters", lambda ctx, region: [])
    monkeypatch.setattr(dr_readiness.data_stores, "describe_rds_snapshots", lambda ctx, region: [{"DBSnapshotIdentifier": "s"}])
    assert dr_readiness.rds_evidence(ctx, "eu-west-1") == {
        "Region": "eu-west-1",
        "RdsInstances": [MULTI_AZ],
        "RdsClusters": [],
        "RdsManualSnapshots": [{"DBSnapshotIdentifier": "s"}],
    }


# --------------------------------------------------------------- discovery
def _subnet_role(*routes) -> tuple[str, str, str]:
    route_tables = [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}], "Routes": list(routes)}]
    return discover._subnet_connectivity({"SubnetId": "subnet-1", "VpcId": "vpc-1"}, route_tables)


@pytest.mark.parametrize(
    "route, role, target, says",
    [
        ({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "vgw-1"}, "Private", "vgw-1", "to the VPN gateway"),
        ({"DestinationCidrBlock": "0.0.0.0/0", "NetworkInterfaceId": "eni-1", "InstanceId": "i-1"}, "Private", "eni-1", "to eni-1, not directly"),
        ({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "vpce-1"}, "Private", "vpce-1", "to vpce-1"),
        ({"DestinationIpv6CidrBlock": "::/0", "EgressOnlyInternetGatewayId": "eigw-1"}, "Private", "eigw-1", "IPv6 outbound only"),
        ({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-gone", "State": "blackhole"}, "Isolated", "", "no 0.0.0.0/0 or ::/0 route"),
    ],
)
def test_subnet_role_follows_any_default_route_not_only_gateways(route, role, target, says):
    """A default route through a VPN gateway or a NAT instance was drawn as
    "Isolated: no 0.0.0.0/0 route", and a blackhole route as a live one."""
    got_role, got_target, label = _subnet_role(route)
    assert (got_role, got_target) == (role, target)
    assert says in label


def test_an_ipv6_internet_route_makes_a_nat_subnet_public():
    role, target, label = _subnet_role(
        {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
        {"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1"},
    )
    assert (role, target) == ("Public", "igw-1") and label.startswith("::/0 via rtb-1")


def test_a_nat_route_outranks_a_transit_gateway_route():
    role, target, _ = _subnet_role(
        {"DestinationIpv6CidrBlock": "::/0", "TransitGatewayId": "tgw-1"},
        {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
    )
    assert (role, target) == ("Private", "nat-1")


def test_discovery_s3_tile_does_not_vouch_for_buckets_it_could_not_read():
    buckets = [{"Name": "open-ok"}, {"Name": "locked", "_Unreadable": ["PublicAccessBlock"]}]
    inventory = {
        "AccountId": "1",
        "Regions": {},
        "Global": {
            "DataStores": {
                "S3Buckets": buckets,
                "PubliclyAccessibleBuckets": [],
                "UnencryptedBuckets": [],
                "BucketsNotRead": [{"Name": "locked", "Settings": ["PublicAccessBlock"]}],
            }
        },
        access.KEY: [],
    }
    report = discover.build_report(inventory, {})
    assert {k.label: k.note for k in report.kpis}["S3 buckets"] == "1 not read; the rest block public access"
    assert "- **Buckets the scan couldn't read:** 1 (see Access Gaps); they are in neither count above" in report.render_markdown()


# ------------------------------------------------- moto: the real wiring
@mock_aws
def test_collect_region_backup_counts_only_copies_to_another_region(ctx, monkeypatch):
    # moto doesn't implement ListProtectedResources or ListBackupJobs; the
    # plans are what this tests.
    monkeypatch.setattr(backup, "list_protected_resources", lambda ctx, region: [])
    monkeypatch.setattr(backup, "list_recent_jobs", lambda ctx, region, by_state=None: [])
    bk = boto3.client("backup", region_name="us-east-1")
    bk.create_backup_vault(BackupVaultName="primary")
    for name, region in (("same", "us-east-1"), ("other", "us-west-2")):
        bk.create_backup_plan(
            BackupPlan={
                "BackupPlanName": name,
                "Rules": [
                    {
                        "RuleName": "r",
                        "TargetBackupVaultName": "primary",
                        "CopyActions": [{"DestinationBackupVaultArn": f"arn:aws:backup:{region}:123456789012:backup-vault:copy"}],
                    }
                ],
            }
        )
    copies = backup.collect_region_backup(ctx, "us-east-1")["PlansWithCrossRegionCopy"]
    assert [p["BackupPlanName"] for p in copies] == ["other"]
