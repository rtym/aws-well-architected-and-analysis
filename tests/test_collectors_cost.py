import importlib.util
import re
import sys
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from shared.awslib.collectors import cost
from tests.stub_helpers import install_stub


def test_add_days_advances_date_correctly():
    assert cost._add_days("2024-01-01", 30) == "2024-01-31"
    assert cost._add_days("2024-02-01", 28) == "2024-02-29"  # 2024 is a leap year
    assert cost._add_days("2024-12-15", 20) == "2025-01-04"  # crosses year boundary


def test_add_days_zero_is_identity():
    assert cost._add_days("2024-06-01", 0) == "2024-06-01"


@mock_aws
def test_cost_and_usage_by_service(ctx):
    ce = boto3.client("ce", region_name="us-east-1")
    ce.get_cost_and_usage(
        TimePeriod={"Start": "2024-01-01", "End": "2024-01-31"},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
    )  # warm up moto's CE backend; real assertions use our wrapper below

    results = cost.cost_and_usage_by_service(ctx, "2024-01-01", "2024-01-31")
    assert isinstance(results, list)


def test_reservation_utilization_returns_default_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_reservation_utilization", service_error_code="AccessDeniedException")

    assert cost.reservation_utilization(ctx, "2024-01-01", "2024-01-31") == {}


def test_rightsizing_recommendations_parses_response(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_response(
        "get_rightsizing_recommendation",
        {
            "Metadata": {"RecommendationId": "abc"},
            "Summary": {"TotalRecommendationCount": "1"},
            "RightsizingRecommendations": [
                {
                    "AccountId": "123456789012",
                    "CurrentInstance": {"ResourceId": "i-123"},
                    "RightsizingType": "Modify",
                }
            ],
        },
    )

    recs = cost.rightsizing_recommendations(ctx)
    assert len(recs) == 1
    assert recs[0]["CurrentInstance"]["ResourceId"] == "i-123"


def test_savings_plans_purchase_recommendation(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_response(
        "get_savings_plans_purchase_recommendation",
        {
            "Metadata": {"RecommendationId": "abc"},
            "SavingsPlansPurchaseRecommendation": {
                "SavingsPlansPurchaseRecommendationDetails": [
                    {"AccountId": "123456789012", "UpfrontCost": "0", "EstimatedMonthlySavingsAmount": "42.50"}
                ]
            },
        },
    )

    rec = cost.savings_plans_purchase_recommendation(ctx)
    detail = rec["SavingsPlansPurchaseRecommendation"]["SavingsPlansPurchaseRecommendationDetails"][0]
    assert detail["EstimatedMonthlySavingsAmount"] == "42.50"


def test_trusted_advisor_requires_business_support_gracefully_handled(ctx):
    support_client, stub = install_stub(ctx, "support", region="us-east-1")
    stub.add_client_error(
        "describe_trusted_advisor_checks", service_error_code="SubscriptionRequiredException"
    )

    assert cost.trusted_advisor_cost_checks(ctx) == []


def test_cost_by_linked_account(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_response(
        "get_cost_and_usage",
        {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Total": {},
                    "Groups": [{"Keys": ["111111111111"], "Metrics": {"UnblendedCost": {"Amount": "10.0", "Unit": "USD"}}}],
                    "Estimated": False,
                }
            ]
        },
    )

    results = cost.cost_by_linked_account(ctx, "2024-01-01", "2024-02-01")
    assert results[0]["Groups"][0]["Keys"] == ["111111111111"]


def test_cost_forecast_returns_dict_default_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_cost_forecast", service_error_code="AccessDeniedException")

    assert cost.cost_forecast(ctx, "2024-01-01", "2024-02-01") == {}


def test_reservation_coverage_returns_dict_default_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_reservation_coverage", service_error_code="AccessDeniedException")

    assert cost.reservation_coverage(ctx, "2024-01-01", "2024-02-01") == {}


def test_savings_plans_utilization_returns_dict_default_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_savings_plans_utilization", service_error_code="AccessDeniedException")

    assert cost.savings_plans_utilization(ctx, "2024-01-01", "2024-02-01") == {}


def test_savings_plans_coverage_returns_dict_default_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_savings_plans_coverage", service_error_code="AccessDeniedException")

    assert cost.savings_plans_coverage(ctx, "2024-01-01", "2024-02-01") == {}


def test_reserved_instance_purchase_recommendation(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_response(
        "get_reservation_purchase_recommendation",
        {"Metadata": {"RecommendationId": "abc"}, "Recommendations": []},
    )

    rec = cost.reserved_instance_purchase_recommendation(ctx)
    assert rec["Metadata"]["RecommendationId"] == "abc"


def test_reserved_instance_purchase_recommendation_returns_dict_default_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_reservation_purchase_recommendation", service_error_code="AccessDeniedException")

    assert cost.reserved_instance_purchase_recommendation(ctx) == {}


def test_anomalies_parses_response(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_response(
        "get_anomalies",
        {
            "Anomalies": [
                {
                    "AnomalyId": "a-1",
                    "AnomalyStartDate": "2024-01-05",
                    "Impact": {"TotalImpact": 42.0, "MaxImpact": 42.0, "TotalImpactPercentage": 10.0},
                    "MonitorArn": "arn:aws:ce::123456789012:anomalymonitor/monitor-1",
                    "AnomalyScore": {"MaxScore": 90.0, "CurrentScore": 80.0},
                }
            ]
        },
    )

    anomalies = cost.anomalies(ctx, "2024-01-01", "2024-02-01")
    assert anomalies[0]["AnomalyId"] == "a-1"


def test_anomalies_returns_empty_list_on_access_denied(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_anomalies", service_error_code="AccessDeniedException")

    assert cost.anomalies(ctx, "2024-01-01", "2024-02-01") == []


def test_compute_optimizer_ec2_recommendations(ctx):
    co_client, stub = install_stub(ctx, "compute-optimizer", region="us-east-1")
    stub.add_response(
        "get_ec2_instance_recommendations",
        {"instanceRecommendations": [{"instanceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "finding": "OVER_PROVISIONED"}]},
    )

    recs = cost.compute_optimizer_ec2_recommendations(ctx, "us-east-1")
    assert recs[0]["finding"] == "OVER_PROVISIONED"


def test_compute_optimizer_ec2_recommendations_returns_empty_on_access_denied(ctx):
    co_client, stub = install_stub(ctx, "compute-optimizer", region="us-east-1")
    stub.add_client_error("get_ec2_instance_recommendations", service_error_code="AccessDeniedException")

    assert cost.compute_optimizer_ec2_recommendations(ctx, "us-east-1") == []


def test_compute_optimizer_ebs_recommendations(ctx):
    co_client, stub = install_stub(ctx, "compute-optimizer", region="us-east-1")
    stub.add_response(
        "get_ebs_volume_recommendations",
        {"volumeRecommendations": [{"volumeArn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-1"}]},
    )

    recs = cost.compute_optimizer_ebs_recommendations(ctx, "us-east-1")
    assert len(recs) == 1


def test_collect_cost_report_wires_every_field(ctx, monkeypatch):
    """Aggregator-level test: verifies collect_cost_report actually calls
    and wires in every sub-collector under the dict keys build_report()
    depends on, without needing ~13 real AWS response stubs."""
    for name, value in [
        ("cost_and_usage_by_service", lambda *a, **k: ["service-data"]),
        ("cost_by_linked_account", lambda *a, **k: ["account-data"]),
        ("cost_forecast", lambda *a, **k: {"forecast": True}),
        ("reservation_utilization", lambda *a, **k: {"ri": True}),
        ("reservation_coverage", lambda *a, **k: {"ri_cov": True}),
        ("savings_plans_utilization", lambda *a, **k: {"sp": True}),
        ("savings_plans_coverage", lambda *a, **k: {"sp_cov": True}),
        ("rightsizing_recommendations", lambda *a, **k: ["rightsizing"]),
        ("savings_plans_purchase_recommendation", lambda *a, **k: {"sp_rec": True}),
        ("reserved_instance_purchase_recommendation", lambda *a, **k: {"ri_rec": True}),
        ("anomalies", lambda *a, **k: ["anomaly"]),
        ("trusted_advisor_cost_checks", lambda *a, **k: ["ta-check"]),
        ("budgets", lambda *a, **k: ["budget"]),
    ]:
        monkeypatch.setattr(cost, name, value)

    report = cost.collect_cost_report(ctx, "2024-01-01", "2024-02-01")

    assert report["CostByService"] == ["service-data"]
    assert report["CostByAccount"] == ["account-data"]
    assert report["Forecast"] == {"forecast": True}
    assert report["ReservationUtilization"] == {"ri": True}
    assert report["ReservationCoverage"] == {"ri_cov": True}
    assert report["SavingsPlansUtilization"] == {"sp": True}
    assert report["SavingsPlansCoverage"] == {"sp_cov": True}
    assert report["RightsizingRecommendations"] == ["rightsizing"]
    assert report["SavingsPlansPurchaseRecommendation"] == {"sp_rec": True}
    assert report["ReservedInstancePurchaseRecommendation"] == {"ri_rec": True}
    assert report["Anomalies"] == ["anomaly"]
    assert report["TrustedAdvisorCostChecks"] == ["ta-check"]
    assert report["Budgets"] == ["budget"]
    assert report["TimePeriod"] == {"Start": "2024-01-01", "End": "2024-02-01"}


# ------------------------------------------------ DataUnavailableException
# Cost Explorer returns DataUnavailableException when there is simply no data
# (no Savings Plans / reservations, or a brand-new account). That is "no
# evidence", not a failure, and used to abort entire collection runs.

ROOT = Path(__file__).resolve().parents[1]

CE_OPTIONAL_COLLECTORS = [
    ("get_cost_forecast", lambda ctx: cost.cost_forecast(ctx, "2024-01-01", "2024-02-01"), {}),
    ("get_reservation_utilization", lambda ctx: cost.reservation_utilization(ctx, "2024-01-01", "2024-02-01"), {}),
    ("get_reservation_coverage", lambda ctx: cost.reservation_coverage(ctx, "2024-01-01", "2024-02-01"), {}),
    ("get_savings_plans_utilization", lambda ctx: cost.savings_plans_utilization(ctx, "2024-01-01", "2024-02-01"), {}),
    ("get_savings_plans_coverage", lambda ctx: cost.savings_plans_coverage(ctx, "2024-01-01", "2024-02-01"), {}),
    ("get_rightsizing_recommendation", lambda ctx: cost.rightsizing_recommendations(ctx), []),
    ("get_savings_plans_purchase_recommendation", lambda ctx: cost.savings_plans_purchase_recommendation(ctx), {}),
    ("get_reservation_purchase_recommendation", lambda ctx: cost.reserved_instance_purchase_recommendation(ctx), {}),
    ("get_anomalies", lambda ctx: cost.anomalies(ctx, "2024-01-01", "2024-02-01"), []),
]


def test_savings_plans_utilization_returns_dict_default_on_data_unavailable(ctx):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_savings_plans_utilization", service_error_code="DataUnavailableException")

    assert cost.savings_plans_utilization(ctx, "2024-01-01", "2024-02-01") == {}


@pytest.mark.parametrize(
    "operation,call,default",
    CE_OPTIONAL_COLLECTORS,
    ids=[op for op, _, _ in CE_OPTIONAL_COLLECTORS],
)
def test_every_optional_ce_collector_returns_default_on_data_unavailable(ctx, operation, call, default):
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error(operation, service_error_code="DataUnavailableException")

    assert call(ctx) == default
    stub.assert_no_pending_responses()


def test_optional_ce_collector_list_covers_every_ce_call_in_cost_module():
    """Guard against drift: a Cost Explorer call added to cost.py must be
    added to CE_OPTIONAL_COLLECTORS (or deliberately excluded here) so its
    DataUnavailableException handling is tested."""
    source = Path(cost.__file__).read_text()
    called = set(re.findall(r"\bce\.(get_\w+)\(", source))
    core = {"get_cost_and_usage"}  # undecorated on purpose -- see below
    assert called - core == {op for op, _, _ in CE_OPTIONAL_COLLECTORS}


def test_savings_plans_utilization_still_raises_unrelated_errors(ctx):
    """The fix must stay narrow: throttling is not "no data"."""
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_savings_plans_utilization", service_error_code="ThrottlingException")

    with pytest.raises(ClientError) as exc:
        cost.savings_plans_utilization(ctx, "2024-01-01", "2024-02-01")
    assert exc.value.response["Error"]["Code"] == "ThrottlingException"


def test_cost_and_usage_by_service_still_raises_data_unavailable(ctx):
    """Core spend data is deliberately not wrapped in ignore_access_denied:
    if it can't be fetched, the report would be meaningless, so fail loudly."""
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_client_error("get_cost_and_usage", service_error_code="DataUnavailableException")

    with pytest.raises(ClientError) as exc:
        cost.cost_and_usage_by_service(ctx, "2024-01-01", "2024-02-01")
    assert exc.value.response["Error"]["Code"] == "DataUnavailableException"


def _stub_ce_with_no_commitment_data(ctx):
    """A CE client for an account with spend but no Savings Plans,
    reservations or other optional data: cost & usage succeeds, every
    optional endpoint raises DataUnavailableException. Responses are queued
    in the order collect_cost_report() calls them."""
    ce_client, stub = install_stub(ctx, "ce", region="us-east-1")
    stub.add_response("get_cost_and_usage", {"ResultsByTime": []})
    stub.add_response("get_cost_and_usage", {"ResultsByTime": []})
    for operation in (
        "get_cost_forecast",
        "get_reservation_utilization",
        "get_reservation_coverage",
        "get_savings_plans_utilization",
        "get_savings_plans_coverage",
        "get_rightsizing_recommendation",
        "get_savings_plans_purchase_recommendation",
        "get_reservation_purchase_recommendation",
        "get_anomalies",
    ):
        stub.add_client_error(operation, service_error_code="DataUnavailableException")
    return stub


def _no_trusted_advisor_or_budgets(monkeypatch):
    monkeypatch.setattr(cost, "trusted_advisor_cost_checks", lambda *a, **k: [])
    monkeypatch.setattr(cost, "budgets", lambda *a, **k: [])


def test_collect_cost_report_tolerates_data_unavailable(ctx, monkeypatch):
    stub = _stub_ce_with_no_commitment_data(ctx)
    _no_trusted_advisor_or_budgets(monkeypatch)

    report = cost.collect_cost_report(ctx, "2024-01-01", "2024-02-01")

    stub.assert_no_pending_responses()
    assert report["SavingsPlansUtilization"] == {}
    assert report["SavingsPlansCoverage"] == {}
    assert report["ReservationUtilization"] == {}
    assert report["ReservationCoverage"] == {}
    assert report["Forecast"] == {}
    assert report["RightsizingRecommendations"] == []
    assert report["Anomalies"] == []


def _load_script(module_name: str, script_path: str):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_analyze_cost_does_not_crash_on_data_unavailable(ctx, monkeypatch):
    analyze_cost = _load_script("ce_unavailable_analyze_cost", "skills/aws-cost-optimization/scripts/analyze_cost.py")
    stub = _stub_ce_with_no_commitment_data(ctx)
    _no_trusted_advisor_or_budgets(monkeypatch)

    data = analyze_cost.collect(ctx, "2024-01-01", "2024-02-01", co_regions=[])
    report = analyze_cost.build_report(data, "2024-01-01", "2024-02-01")

    stub.assert_no_pending_responses()
    assert data["CostReport"]["SavingsPlansUtilization"] == {}
    coverage = next(s for s in report.sections if s.title == "Reservation & Savings Plans Coverage")
    assert "No Reserved Instance or Savings Plans utilization data returned" in coverage.body_md


def test_collect_evidence_does_not_crash_on_data_unavailable(ctx, monkeypatch):
    collect_evidence = _load_script(
        "ce_unavailable_collect_evidence", "skills/aws-well-architected-review/scripts/collect_evidence.py"
    )
    stub = _stub_ce_with_no_commitment_data(ctx)
    _no_trusted_advisor_or_budgets(monkeypatch)
    # Only Cost Explorer is under test; every other collector is irrelevant here.
    for module, name in [
        (collect_evidence.vpc, "collect_region_network"),
        (collect_evidence.compute, "collect_region_compute"),
        (collect_evidence.containers, "collect_region_containers"),
        (collect_evidence.data_stores, "collect_region_data_stores"),
        (collect_evidence.security, "collect_region_security"),
        (collect_evidence.backup, "collect_region_backup"),
        (collect_evidence.observability, "collect_region_observability"),
        (collect_evidence.quotas, "common_quota_values"),
        (collect_evidence.security, "collect_global_security"),
        (collect_evidence.data_stores, "collect_global_data_stores"),
        (collect_evidence.cloudtrail, "cloudtrail_posture"),
    ]:
        monkeypatch.setattr(module, name, lambda *a, **k: {})

    evidence = collect_evidence.collect(ctx, ["us-east-1"], workload_id=None)

    stub.assert_no_pending_responses()
    assert evidence["Global"]["Cost"]["SavingsPlansUtilization"] == {}
    assert evidence["Global"]["Cost"]["ReservationUtilization"] == {}
