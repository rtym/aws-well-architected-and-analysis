from shared.awslib.collectors import quotas
from tests.stub_helpers import install_stub


def test_common_quota_values_uses_applied_quota_when_present(ctx):
    sq, stub = install_stub(ctx, "service-quotas")
    for service_code, quota_code, _label in quotas.COMMON_QUOTAS:
        stub.add_response(
            "get_service_quota",
            {
                "Quota": {
                    "ServiceCode": service_code,
                    QUOTA_CODE_KEY: quota_code,
                    "QuotaName": "x",
                    "Value": 42.0,
                    "Unit": "None",
                    "Adjustable": True,
                    "GlobalQuota": False,
                }
            },
            expected_params={"ServiceCode": service_code, "QuotaCode": quota_code},
        )

    results = quotas.common_quota_values(ctx, "us-east-1")

    assert len(results) == len(quotas.COMMON_QUOTAS)
    assert all(r["Value"] == 42.0 for r in results)


QUOTA_CODE_KEY = "QuotaCode"


def test_common_quota_values_falls_back_to_default_when_not_applied(ctx):
    sq, stub = install_stub(ctx, "service-quotas")
    service_code, quota_code, _label = quotas.COMMON_QUOTAS[0]
    stub.add_client_error(
        "get_service_quota",
        service_error_code="NoSuchResourceException",
        expected_params={"ServiceCode": service_code, "QuotaCode": quota_code},
    )
    stub.add_response(
        "get_aws_default_service_quota",
        {
            "Quota": {
                "ServiceCode": service_code,
                "QuotaCode": quota_code,
                "QuotaName": "x",
                "Value": 20.0,
                "Unit": "None",
                "Adjustable": True,
                "GlobalQuota": False,
            }
        },
        expected_params={"ServiceCode": service_code, "QuotaCode": quota_code},
    )
    # Every other configured quota is skipped by not queuing a response for
    # it -- Stubber would raise on an unexpected call, so scope this test to
    # exactly one quota lookup by only checking the first COMMON_QUOTAS entry.
    for other_service_code, other_quota_code, _ in quotas.COMMON_QUOTAS[1:]:
        stub.add_client_error(
            "get_service_quota",
            service_error_code="NoSuchResourceException",
            expected_params={"ServiceCode": other_service_code, "QuotaCode": other_quota_code},
        )
        stub.add_client_error(
            "get_aws_default_service_quota",
            service_error_code="NoSuchResourceException",
            expected_params={"ServiceCode": other_service_code, "QuotaCode": other_quota_code},
        )

    results = quotas.common_quota_values(ctx, "us-east-1")

    first = next(r for r in results if r["QuotaCode"] == quota_code)
    assert first["Value"] == 20.0


def test_common_quota_values_returns_empty_on_access_denied(ctx):
    sq, stub = install_stub(ctx, "service-quotas")
    stub.add_client_error(
        "get_service_quota",
        service_error_code="AccessDeniedException",
        expected_params={"ServiceCode": quotas.COMMON_QUOTAS[0][0], "QuotaCode": quotas.COMMON_QUOTAS[0][1]},
    )

    assert quotas.common_quota_values(ctx, "us-east-1") == []


def test_pending_quota_increase_requests(ctx):
    sq, stub = install_stub(ctx, "service-quotas")
    stub.add_response(
        "list_requested_service_quota_change_history",
        {
            "RequestedQuotas": [
                {
                    "Id": "req-1",
                    "ServiceCode": "ec2",
                    "QuotaCode": "L-1216C47A",
                    "DesiredValue": 100.0,
                    "Status": "PENDING",
                }
            ]
        },
        expected_params={"Status": "PENDING"},
    )

    results = quotas.pending_quota_increase_requests(ctx, "us-east-1")
    assert results[0]["Id"] == "req-1"
