"""AWS Well-Architected Tool API -- reads/writes actual workloads defined in
the account's WA Tool console (wellarchitected service), so an evidence-based
review can optionally be recorded as real answers/risks against a workload
instead of only living in a Markdown report.
"""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, manual_paginate

PILLAR_IDS = (
    "operationalExcellence",
    "security",
    "reliability",
    "performanceEfficiency",
    "costOptimization",
    "sustainability",
)


@ignore_access_denied(default=list)
def list_workloads(ctx: AwsContext, region: str) -> list[dict]:
    wa = ctx.client("wellarchitected", region=region)
    return list(manual_paginate(wa, "list_workloads", "WorkloadSummaries"))


@ignore_access_denied(default=lambda: None)
def get_workload(ctx: AwsContext, region: str, workload_id: str) -> dict:
    wa = ctx.client("wellarchitected", region=region)
    return wa.get_workload(WorkloadId=workload_id)["Workload"]


@ignore_access_denied(default=list)
def list_answers(ctx: AwsContext, region: str, workload_id: str, lens_alias: str = "wellarchitected") -> list[dict]:
    wa = ctx.client("wellarchitected", region=region)
    return list(
        manual_paginate(
            wa,
            "list_answers",
            "AnswerSummaries",
            WorkloadId=workload_id,
            LensAlias=lens_alias,
        )
    )


@ignore_access_denied(default=list)
def list_lens_review_improvements(
    ctx: AwsContext, region: str, workload_id: str, pillar_id: str, lens_alias: str = "wellarchitected"
) -> list[dict]:
    wa = ctx.client("wellarchitected", region=region)
    return list(
        manual_paginate(
            wa,
            "list_lens_review_improvements",
            "ImprovementSummaries",
            WorkloadId=workload_id,
            LensAlias=lens_alias,
            PillarId=pillar_id,
        )
    )


def update_answer(
    ctx: AwsContext,
    region: str,
    workload_id: str,
    question_id: str,
    selected_choices: list[str],
    notes: str = "",
    lens_alias: str = "wellarchitected",
) -> dict:
    """Records evidence-based answers back into the WA Tool. Only call this
    when the user has explicitly asked to persist findings against a real
    workload -- it mutates account state."""
    wa = ctx.client("wellarchitected", region=region)
    return wa.update_answer(
        WorkloadId=workload_id,
        LensAlias=lens_alias,
        QuestionId=question_id,
        SelectedChoices=selected_choices,
        Notes=notes,
    )


def collect_workload_snapshot(ctx: AwsContext, region: str, workload_id: str) -> dict:
    workload = get_workload(ctx, region, workload_id)
    answers = list_answers(ctx, region, workload_id)
    improvements = {
        pillar: list_lens_review_improvements(ctx, region, workload_id, pillar)
        for pillar in PILLAR_IDS
    }
    return {"Workload": workload, "Answers": answers, "ImprovementsByPillar": improvements}
