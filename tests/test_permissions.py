"""PERMISSIONS.md's least-privilege policy must grant every AWS API call the
collectors make.

CONTRIBUTING asks contributors to add an IAM action for each new API call;
this enforces it. The policy once listed `accessanalyzer:ListAnalyzers` and
`accessanalyzer:ListFindings` -- the boto3 client name, not the IAM prefix
`access-analyzer` -- so under Option B the Access Analyzer check quietly
returned nothing, and no test noticed.

The scan is static: it maps each `x = ctx.client("svc")` variable in a
collector module to its service, then resolves `x.operation(...)` and
`paginate(x, "operation", ...)` calls through botocore's own method-to-API
mapping.
"""
from __future__ import annotations

import fnmatch
import json
import re
from functools import cache
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_ROOT = ROOT / "shared" / "awslib"

# IAM prefixes that differ from the service's signing name.
IAM_PREFIX_OVERRIDES = {"monitoring": "cloudwatch"}

# API operations whose IAM action has a different name.
IAM_ACTION_FOR_OPERATION = {
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",
    ("s3", "GetBucketReplication"): "s3:GetReplicationConfiguration",
    ("s3", "GetPublicAccessBlock"): "s3:GetBucketPublicAccessBlock",
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3control", "GetPublicAccessBlock"): "s3:GetAccountPublicAccessBlock",
    ("budgets", "DescribeBudgets"): "budgets:ViewBudget",
    ("accessanalyzer", "ListFindingsV2"): "access-analyzer:ListFindings",
}

# The one mutating call, left out of the read-only policy on purpose (see
# PERMISSIONS.md's notes and CONTRIBUTING section 1).
DELIBERATELY_UNGRANTED = {("wellarchitected", "UpdateAnswer")}

_ASSIGN = re.compile(r'\b(\w+)\s*=\s*(?:self|ctx)\.client\(\s*"([a-z0-9-]+)"')
_CHAINED = re.compile(r'(?:self|ctx)\.client\(\s*"([a-z0-9-]+)"[^)]*\)\.(\w+)\(')
_CALL = re.compile(r"\b(\w+)\.(\w+)\(")
_PAGINATED = re.compile(r'\b(?:manual_)?paginate\(\s*(\w+),\s*"(\w+)"')


@cache
def _client(service: str):
    return boto3.Session(
        region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    ).client(service)


def _iam_prefix(service: str) -> str:
    metadata = _client(service).meta.service_model.metadata
    signing = metadata.get("signingName") or metadata["endpointPrefix"]
    return IAM_PREFIX_OVERRIDES.get(signing, signing)


def _collector_calls() -> set[tuple[str, str]]:
    """(boto3 service name, API operation name) for every call site."""
    found = set()
    for path in sorted(COLLECTOR_ROOT.rglob("*.py")):
        text = path.read_text()
        var_service: dict[str, str] = {}
        for var, service in _ASSIGN.findall(text):
            assert var_service.get(var, service) == service, (
                f"{path.name}: variable {var!r} holds two different clients; "
                "rename one so this scan can tell their calls apart"
            )
            var_service[var] = service
        candidates = list(_CHAINED.findall(text))
        candidates += [(var_service[v], op) for v, op in _CALL.findall(text) if v in var_service]
        candidates += [(var_service[v], op) for v, op in _PAGINATED.findall(text) if v in var_service]
        for service, method in candidates:
            api_name = _client(service).meta.method_to_api_mapping.get(method)
            if api_name:
                found.add((service, api_name))
    return found


def _policy_actions() -> list[str]:
    text = (ROOT / "PERMISSIONS.md").read_text()
    policy = json.loads(re.search(r"```json\n(.*?)\n```", text, re.S).group(1))
    actions = []
    for statement in policy["Statement"]:
        assert statement["Effect"] == "Allow"
        actions.extend(statement["Action"])
    return actions


def _granted(action: str, policy_actions: list[str]) -> bool:
    # IAM matches action names case-insensitively, with * and ? wildcards.
    return any(fnmatch.fnmatchcase(action.lower(), granted.lower()) for granted in policy_actions)


def _required_action(service: str, operation: str) -> str:
    return IAM_ACTION_FOR_OPERATION.get((service, operation), f"{_iam_prefix(service)}:{operation}")


def test_scan_sees_every_collector_service():
    """Guard the guard: if the regexes stop matching (a refactor that builds
    clients differently), this fails instead of the main test passing
    vacuously."""
    calls = _collector_calls()
    services_built = {
        service
        for path in COLLECTOR_ROOT.rglob("*.py")
        for service in re.findall(r'\.client\(\s*"([a-z0-9-]+)"', path.read_text())
    }
    assert services_built == {service for service, _ in calls}
    assert len(calls) > 100


@pytest.mark.parametrize("service,operation", sorted(_collector_calls()))
def test_policy_grants_every_collector_call(service, operation):
    if (service, operation) in DELIBERATELY_UNGRANTED:
        assert not _granted(_required_action(service, operation), _policy_actions())
        return
    action = _required_action(service, operation)
    assert _granted(action, _policy_actions()), (
        f"{service}.{operation} is called by a collector but PERMISSIONS.md "
        f"doesn't grant {action}"
    )


def test_every_policy_prefix_is_a_real_iam_prefix():
    """A boto3 client name in place of the IAM prefix (`accessanalyzer:`)
    grants nothing; IAM accepts the policy without complaint."""
    valid = {_iam_prefix(service) for service, _ in _collector_calls()}
    for action in _policy_actions():
        assert action.split(":", 1)[0] in valid, action


def test_every_explicit_policy_action_names_a_real_operation():
    """Catches misspelled action names, which IAM also accepts silently."""
    services_by_prefix: dict[str, list[str]] = {}
    for service, _ in _collector_calls():
        services_by_prefix.setdefault(_iam_prefix(service), []).append(service)
    iam_only_names = set(IAM_ACTION_FOR_OPERATION.values())
    for action in _policy_actions():
        if "*" in action or action in iam_only_names:
            continue
        prefix, name = action.split(":", 1)
        operations = {
            op
            for service in services_by_prefix[prefix]
            for op in _client(service).meta.service_model.operation_names
        }
        assert name in operations, action
