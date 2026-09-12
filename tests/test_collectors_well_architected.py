from shared.awslib.collectors import well_architected as wa
from tests.stub_helpers import install_stub


def test_update_answer_records_evidence_against_a_real_workload(ctx):
    """update_answer is the one mutating call in this codebase -- only ever
    invoked when the user explicitly asks the WA review skill to persist
    findings. Verify it sends exactly the fields the WA Tool API expects."""
    client, stub = install_stub(ctx, "wellarchitected", region="us-east-1")
    workload_id = "1" * 32
    stub.add_response(
        "update_answer",
        {"WorkloadId": workload_id, "LensAlias": "wellarchitected"},
        expected_params={
            "WorkloadId": workload_id,
            "LensAlias": "wellarchitected",
            "QuestionId": "SEC_1",
            "SelectedChoices": ["choice-a"],
            "Notes": "evidence-based finding",
        },
    )

    result = wa.update_answer(
        ctx, "us-east-1", workload_id, "SEC_1", ["choice-a"], notes="evidence-based finding"
    )

    assert result["WorkloadId"] == workload_id


def test_list_workloads_returns_empty_when_not_available(ctx):
    client, stub = install_stub(ctx, "wellarchitected", region="us-east-1")
    stub.add_client_error("list_workloads", service_error_code="AccessDeniedException")

    assert wa.list_workloads(ctx, "us-east-1") == []


def test_collect_workload_snapshot(ctx):
    client, stub = install_stub(ctx, "wellarchitected", region="us-east-1")
    stub.add_response(
        "get_workload",
        {
            "Workload": {
                "WorkloadId": "12345678901234567890123456789012",
                "WorkloadName": "demo",
                "WorkloadArn": "arn:aws:wellarchitected:us-east-1:123456789012:workload/w-1",
                "Environment": "PRODUCTION",
                "UpdatedAt": "2024-01-01T00:00:00.000Z",
                "Lenses": ["wellarchitected"],
                "Owner": "123456789012",
            }
        },
        expected_params={"WorkloadId": "12345678901234567890123456789012"},
    )
    stub.add_response("list_answers", {"AnswerSummaries": []}, expected_params={"WorkloadId": "12345678901234567890123456789012", "LensAlias": "wellarchitected"})
    for pillar in wa.PILLAR_IDS:
        stub.add_response(
            "list_lens_review_improvements",
            {"ImprovementSummaries": []},
            expected_params={
                "WorkloadId": "12345678901234567890123456789012",
                "LensAlias": "wellarchitected",
                "PillarId": pillar,
            },
        )

    snapshot = wa.collect_workload_snapshot(ctx, "us-east-1", "12345678901234567890123456789012")

    assert snapshot["Workload"]["WorkloadName"] == "demo"
    assert set(snapshot["ImprovementsByPillar"]) == set(wa.PILLAR_IDS)
