from shared.awslib.collectors import security
from tests.stub_helpers import install_stub


def test_guardduty_findings_across_one_detector(ctx):
    gd, stub = install_stub(ctx, "guardduty")
    stub.add_response("list_detectors", {"DetectorIds": ["det-1"]})
    stub.add_response(
        "list_findings",
        {"FindingIds": ["f-1", "f-2"]},
        expected_params={"DetectorId": "det-1"},
    )
    base_finding = {
        "AccountId": "123456789012",
        "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-1/finding/f",
        "CreatedAt": "2024-01-01T00:00:00.000Z",
        "UpdatedAt": "2024-01-01T00:00:00.000Z",
        "Region": "us-east-1",
        "Resource": {},
        "SchemaVersion": "2.0",
    }
    stub.add_response(
        "get_findings",
        {
            "Findings": [
                {**base_finding, "Id": "f-1", "Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 5.0},
                {**base_finding, "Id": "f-2", "Type": "Trojan:EC2/DNSDataExfiltration", "Severity": 8.0},
            ]
        },
        expected_params={"DetectorId": "det-1", "FindingIds": ["f-1", "f-2"]},
    )

    findings = security.guardduty_findings(ctx, "us-east-1")

    assert len(findings) == 2
    assert findings[0]["Type"].startswith("Recon:")


def test_guardduty_findings_paginates_across_pages_and_batches_get_findings(ctx):
    """list_findings returns 2 pages (80 IDs total via NextToken); get_findings
    can only take <=50 IDs per call, so this must batch into two calls."""
    gd, stub = install_stub(ctx, "guardduty")
    page1_ids = [f"f-{i}" for i in range(1, 51)]
    page2_ids = [f"f-{i}" for i in range(51, 81)]
    stub.add_response("list_detectors", {"DetectorIds": ["det-1"]})
    stub.add_response(
        "list_findings",
        {"FindingIds": page1_ids, "NextToken": "tok-1"},
        expected_params={"DetectorId": "det-1"},
    )
    stub.add_response(
        "list_findings",
        {"FindingIds": page2_ids},
        expected_params={"DetectorId": "det-1", "NextToken": "tok-1"},
    )
    base_finding = {
        "AccountId": "123456789012",
        "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-1/finding/f",
        "CreatedAt": "2024-01-01T00:00:00.000Z",
        "UpdatedAt": "2024-01-01T00:00:00.000Z",
        "Region": "us-east-1",
        "Resource": {},
        "SchemaVersion": "2.0",
        "Type": "Recon:EC2/PortProbeUnprotectedPort",
        "Severity": 2.0,
    }
    stub.add_response(
        "get_findings",
        {"Findings": [{**base_finding, "Id": fid} for fid in page1_ids]},
        expected_params={"DetectorId": "det-1", "FindingIds": page1_ids},
    )
    stub.add_response(
        "get_findings",
        {"Findings": [{**base_finding, "Id": fid} for fid in page2_ids]},
        expected_params={"DetectorId": "det-1", "FindingIds": page2_ids},
    )

    findings = security.guardduty_findings(ctx, "us-east-1", max_findings=200)

    assert len(findings) == 80
    assert {f["Id"] for f in findings} == set(page1_ids) | set(page2_ids)


def test_guardduty_findings_stops_at_max_findings_across_detectors(ctx):
    """Two detectors each offering more findings than needed -- the second
    detector's list_findings/get_findings should never be called once the
    cap is already reached by the first."""
    gd, stub = install_stub(ctx, "guardduty")
    stub.add_response("list_detectors", {"DetectorIds": ["det-1", "det-2"]})
    stub.add_response(
        "list_findings",
        {"FindingIds": [f"f-{i}" for i in range(1, 11)]},
        expected_params={"DetectorId": "det-1"},
    )
    base_finding = {
        "AccountId": "123456789012",
        "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-1/finding/f",
        "CreatedAt": "2024-01-01T00:00:00.000Z",
        "UpdatedAt": "2024-01-01T00:00:00.000Z",
        "Region": "us-east-1",
        "Resource": {},
        "SchemaVersion": "2.0",
        "Type": "Recon:EC2/PortProbeUnprotectedPort",
        "Severity": 2.0,
    }
    ids = [f"f-{i}" for i in range(1, 11)]
    stub.add_response(
        "get_findings",
        {"Findings": [{**base_finding, "Id": fid} for fid in ids]},
        expected_params={"DetectorId": "det-1", "FindingIds": ids},
    )
    # No stub queued for det-2 -- if the code called list_findings/get_findings
    # for det-2 anyway, Stubber would raise StubAssertionError (queue empty).

    findings = security.guardduty_findings(ctx, "us-east-1", max_findings=10)

    assert len(findings) == 10


def test_guardduty_findings_returns_empty_when_access_denied(ctx):
    gd, stub = install_stub(ctx, "guardduty")
    stub.add_client_error("list_detectors", service_error_code="AccessDeniedException")

    assert security.guardduty_detector_ids(ctx, "us-east-1") == []


def test_securityhub_findings_filters_active_high_severity(ctx):
    sh, stub = install_stub(ctx, "securityhub")
    stub.add_response(
        "get_findings",
        {
            "Findings": [
                {
                    "SchemaVersion": "2018-10-08",
                    "Id": "1",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "GeneratorId": "gen-1",
                    "AwsAccountId": "123456789012",
                    "Types": ["Software and Configuration Checks"],
                    "CreatedAt": "2024-01-01T00:00:00.000Z",
                    "UpdatedAt": "2024-01-01T00:00:00.000Z",
                    "Severity": {"Label": "HIGH"},
                    "Title": "Exposed S3 bucket",
                    "Description": "Bucket allows public read",
                    "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::demo"}],
                }
            ]
        },
    )

    findings = security.securityhub_findings(ctx, "us-east-1")

    assert len(findings) == 1
    assert findings[0]["Title"] == "Exposed S3 bucket"


def test_securityhub_standards_summary_counts_enabled_controls(ctx):
    sh, stub = install_stub(ctx, "securityhub")
    stub.add_response(
        "get_enabled_standards",
        {
            "StandardsSubscriptions": [
                {
                    "StandardsSubscriptionArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations/v/1.2.0",
                    "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations/v/1.2.0",
                    "StandardsInput": {},
                    "StandardsStatus": "READY",
                }
            ]
        },
    )
    stub.add_response(
        "describe_standards_controls",
        {
            "Controls": [
                {"ControlId": "CIS.1.1", "ControlStatus": "ENABLED"},
                {"ControlId": "CIS.1.2", "ControlStatus": "DISABLED"},
            ]
        },
    )

    summary = security.securityhub_standards_summary(ctx, "us-east-1")

    assert summary[0]["ControlCount"] == 2
    assert summary[0]["EnabledControlCount"] == 1


def test_access_analyzer_findings_across_analyzers(ctx):
    aa, stub = install_stub(ctx, "accessanalyzer")
    stub.add_response(
        "list_analyzers",
        {
            "analyzers": [
                {
                    "arn": "arn:analyzer/1",
                    "name": "default",
                    "type": "ACCOUNT",
                    "status": "ACTIVE",
                    "createdAt": "2024-01-01T00:00:00.000Z",
                }
            ]
        },
    )
    stub.add_response(
        "list_findings",
        {
            "findings": [
                {
                    "id": "find-1",
                    "resourceType": "AWS::S3::Bucket",
                    "condition": {},
                    "createdAt": "2024-01-01T00:00:00.000Z",
                    "analyzedAt": "2024-01-01T00:00:00.000Z",
                    "updatedAt": "2024-01-01T00:00:00.000Z",
                    "status": "ACTIVE",
                    "resourceOwnerAccount": "123456789012",
                }
            ]
        },
    )

    findings = security.access_analyzer_findings(ctx, "us-east-1")

    assert len(findings) == 1
    assert findings[0]["resourceType"] == "AWS::S3::Bucket"


def test_config_rule_compliance_not_implemented_service_still_handled(ctx):
    cfg, stub = install_stub(ctx, "config")
    stub.add_response(
        "describe_compliance_by_config_rule",
        {
            "ComplianceByConfigRules": [
                {"ConfigRuleName": "s3-bucket-public-read-prohibited", "Compliance": {"ComplianceType": "NON_COMPLIANT"}}
            ]
        },
    )

    result = security.config_rule_compliance(ctx, "us-east-1")

    assert result[0]["ConfigRuleName"] == "s3-bucket-public-read-prohibited"
