from shared.awslib.collectors import network_traffic
from tests.stub_helpers import install_stub


def test_run_insights_query_parses_field_value_rows(ctx):
    logs_client, stub = install_stub(ctx, "logs", region="us-east-1")
    stub.add_response("start_query", {"queryId": "q-1"})
    stub.add_response(
        "get_query_results",
        {
            "results": [
                [
                    {"field": "srcAddr", "value": "10.0.0.5"},
                    {"field": "dstAddr", "value": "10.0.0.9"},
                    {"field": "bytes", "value": "12345"},
                ]
            ],
            "status": "Complete",
        },
    )

    rows = network_traffic.run_insights_query(
        ctx, "us-east-1", "/vpc/flowlogs", "fields srcAddr", 0, 100
    )

    assert rows == [{"srcAddr": "10.0.0.5", "dstAddr": "10.0.0.9", "bytes": "12345"}]


def test_analyze_flow_logs_flags_port_scan_candidates(ctx, monkeypatch):
    def fake_query(_ctx, _region, _log_group, query, _start, _end, timeout_s=60):
        if "distinctPorts" in query:
            return [
                {"srcAddr": "10.0.0.5", "distinctPorts": "42"},
                {"srcAddr": "10.0.0.6", "distinctPorts": "3"},
            ]
        return []

    monkeypatch.setattr(network_traffic, "run_insights_query", fake_query)

    result = network_traffic.analyze_flow_logs(ctx, "us-east-1", "/vpc/flowlogs", 0, 100)

    assert result["port_scan_candidates"] == [{"srcAddr": "10.0.0.5", "distinctPorts": "42"}]


def test_as_int_parses_numeric_strings_and_floats():
    assert network_traffic._as_int("42") == 42
    assert network_traffic._as_int("3.0") == 3
    assert network_traffic._as_int(7) == 7


def test_as_int_returns_zero_for_missing_or_unparseable_values():
    assert network_traffic._as_int(None) == 0
    assert network_traffic._as_int("") == 0
    assert network_traffic._as_int("not-a-number") == 0


def test_network_findings_filters_by_type_prefix(ctx, monkeypatch):
    fake_findings = [
        {"Id": "1", "Type": "Recon:EC2/PortProbeUnprotectedPort"},
        {"Id": "2", "Type": "Policy:IAMUser/RootCredentialUsage"},
        {"Id": "3", "Type": "Trojan:EC2/DNSDataExfiltration"},
    ]
    monkeypatch.setattr(network_traffic, "guardduty_findings", lambda *a, **k: fake_findings)

    result = network_traffic.network_findings(ctx, "us-east-1")

    assert {f["Id"] for f in result} == {"1", "3"}
