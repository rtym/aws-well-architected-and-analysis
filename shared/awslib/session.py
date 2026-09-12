"""AWS session/client helpers.

All collectors go through here so they inherit the exact same credential
chain the AWS CLI uses (profiles, SSO, env vars, instance/task roles) via
boto3 -- no separate credential handling to keep in sync.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, NoCredentialsError

RETRY_CONFIG = BotoConfig(retries={"max_attempts": 8, "mode": "adaptive"})


@dataclass
class AwsContext:
    """Bundles a boto3 session plus the account/region scope for a run."""

    profile: str | None = None
    region: str | None = None
    _session: boto3.Session | None = field(default=None, repr=False, compare=False)
    _client_cache: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def session(self) -> boto3.Session:
        if self._session is None:
            self._session = boto3.Session(profile_name=self.profile, region_name=self.region)
        return self._session

    def client(self, service: str, region: str | None = None):
        key = (service, region or self.region)
        if key not in self._client_cache:
            self._client_cache[key] = self.session.client(
                service, region_name=region or self.region, config=RETRY_CONFIG
            )
        return self._client_cache[key]

    def account_id(self) -> str:
        return self.client("sts").get_caller_identity()["Account"]

    def enabled_regions(self) -> list[str]:
        """Regions enabled for this account (opt-in regions included)."""
        ec2 = self.client("ec2", region=self.region or "us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])


def ignore_access_denied(default=None):
    """Decorator: swallow AccessDenied/UnauthorizedOperation/OptInRequired so one
    missing permission or unavailable service (e.g. GuardDuty not enabled) doesn't
    abort an entire collection run. Returns `default` and records the error on
    the result via the caller's own error-collection convention instead.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (ClientError, NoCredentialsError) as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in {
                    "AccessDenied",
                    "AccessDeniedException",
                    "UnauthorizedOperation",
                    "OptInRequired",
                    "SubscriptionRequiredException",
                    "InvalidAction",
                    "InvalidAccessException",
                    "AWSOrganizationsNotInUseException",
                }:
                    return default() if callable(default) else default
                raise

        return wrapper

    return decorator


def paginate(client, operation: str, result_key: str, **kwargs):
    """Yield items across all pages for a paginated boto3 operation."""
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


def manual_paginate(client, operation: str, result_key: str, token_arg: str = "NextToken", token_field: str = "NextToken", **kwargs):
    """Fallback for operations with no botocore paginator config (e.g. some
    newer `wellarchitected` APIs) but that still return a NextToken."""
    method = getattr(client, operation)
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs[token_arg] = next_token
        page = method(**call_kwargs)
        yield from page.get(result_key, [])
        next_token = page.get(token_field)
        if not next_token:
            break
