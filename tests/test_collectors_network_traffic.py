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
            ], "Complete"
        return [], "Complete"

    monkeypatch.setattr(network_traffic, "query_with_status", fake_query)

    result = network_traffic.analyze_flow_logs(ctx, "us-east-1", "/vpc/flowlogs", 0, 100)

    assert result["port_scan_candidates"] == [{"srcAddr": "10.0.0.5", "distinctPorts": "42"}]
    assert result["incomplete_queries"] == []


def test_analyze_flow_logs_names_the_queries_that_did_not_finish(ctx, monkeypatch):
    """A query that timed out returns no rows, which the report would show
    as "no rejected traffic". A denied query is not listed here: it is in
    the Access Gaps section already."""
    statuses = {"rejected_traffic": "Timeout", "top_talkers_by_bytes": "Running", "traffic_by_protocol": "Denied"}

    def fake_query(_ctx, _region, _log_group, query, _start, _end, timeout_s=60):
        name = next(n for n, q in network_traffic.QUERIES.items() if q == query)
        return [], statuses.get(name, "Complete")

    monkeypatch.setattr(network_traffic, "query_with_status", fake_query)
    result = network_traffic.analyze_flow_logs(ctx, "us-east-1", "/vpc/flowlogs", 0, 100)
    assert result["incomplete_queries"] == [
        {"Query": "top_talkers_by_bytes", "Status": "Running"},
        {"Query": "rejected_traffic", "Status": "Timeout"},
    ]


def test_a_denied_insights_query_returns_no_rows_and_is_recorded(ctx):
    _, stub = install_stub(ctx, "logs", region="us-east-1")
    stub.add_client_error("start_query", service_error_code="AccessDeniedException")
    stub.add_client_error("start_query", service_error_code="AccessDeniedException")
    assert network_traffic.query_with_status(ctx, "us-east-1", "/vpc/fl", "q", 0, 1) == ([], "Denied")
    assert network_traffic.run_insights_query(ctx, "us-east-1", "/vpc/fl", "q", 0, 1) == []
    assert [d["Operation"] for d in ctx.denied] == ["StartQuery"]


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


def test_run_insights_query_polls_until_complete(ctx, monkeypatch):
    """Logs Insights queries are asynchronous: the first poll usually comes
    back Running. The collector must keep polling (without a real 2s sleep
    in tests) and only parse rows from the terminal response."""
    from shared.awslib.collectors import network_traffic as nt

    monkeypatch.setattr(nt.time, "sleep", lambda s: None)
    logs_client, stub = install_stub(ctx, "logs", region="us-east-1")
    stub.add_response("start_query", {"queryId": "q-1"})
    stub.add_response("get_query_results", {"status": "Running", "results": []})
    stub.add_response(
        "get_query_results",
        {
            "status": "Complete",
            "results": [[{"field": "srcAddr", "value": "10.0.0.5"}, {"field": "totalBytes", "value": "99"}]],
        },
    )

    rows = nt.run_insights_query(ctx, "us-east-1", "/vpc/fl", "stats ...", 0, 100)

    assert rows == [{"srcAddr": "10.0.0.5", "totalBytes": "99"}]
    stub.assert_no_pending_responses()


def test_run_insights_query_stops_on_timeout_status(ctx, monkeypatch):
    """"Timeout" is a terminal query state but wasn't in the stop list, so a
    timed-out query kept polling for the full local timeout."""
    logs, stub = install_stub(ctx, "logs", region="us-east-1")
    stub.add_response("start_query", {"queryId": "q-1"})
    stub.add_response("get_query_results", {"status": "Timeout", "results": []}, {"queryId": "q-1"})
    sleeps = []
    monkeypatch.setattr(network_traffic.time, "sleep", sleeps.append)

    assert network_traffic.run_insights_query(ctx, "us-east-1", "flow-logs", "stats count(*)", 0, 60) == []
    assert sleeps == []
    stub.assert_no_pending_responses()
