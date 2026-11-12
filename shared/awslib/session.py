"""AWS session/client helpers.

All collectors go through here so they inherit the exact same credential
chain the AWS CLI uses (profiles, SSO, env vars, instance/task roles) via
boto3 -- no separate credential handling to keep in sync.
"""
from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass, field

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, NoCredentialsError

RETRY_CONFIG = BotoConfig(retries={"max_attempts": 8, "mode": "adaptive"})

# Error codes that mean "this identity may not make the call". The other
# codes `ignore_access_denied` swallows mean the service isn't in use, which
# is an answer; these mean the answer is unknown.
PERMISSION_DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"})


@dataclass
class AwsContext:
    """Bundles a boto3 session plus the account/region scope for a run."""

    profile: str | None = None
    region: str | None = None
    _session: boto3.Session | None = field(default=None, repr=False, compare=False)
    _client_cache: dict = field(default_factory=dict, repr=False, compare=False)
    _account_id: str | None = field(default=None, repr=False, compare=False)
    # Calls this run was not allowed to make, one entry per collector,
    # operation and region. Reports list them, and scored checks treat the
    # evidence behind them as unread instead of as empty.
    denied: list = field(default_factory=list, repr=False, compare=False)

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

    def record_denied(
        self, collector: str, region: str | None, code: str, operation: str | None = None, resource: str | None = None
    ) -> None:
        entry = {"Collector": collector, "Operation": operation, "Region": region or "global", "Code": code}
        if resource:
            entry["Resource"] = resource
        if entry not in self.denied:
            self.denied.append(entry)

    def account_id(self) -> str:
        # Several per-region collectors need the account ID; one STS call
        # per run is enough.
        if self._account_id is None:
            self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id

    def enabled_regions(self) -> list[str]:
        """Regions enabled for this account (opt-in regions included)."""
        ec2 = self.client("ec2", region=self.region or "us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])


def ignore_access_denied(default=None):
    """Decorator: swallow AccessDenied/UnauthorizedOperation/OptInRequired so one
    missing permission or unavailable service (e.g. GuardDuty not enabled) doesn't
    abort an entire collection run. Returns `default` instead.

    A permission error (`PERMISSION_DENIED_CODES`) is also recorded on the
    `AwsContext` the collector was called with, in `ctx.denied`: the default
    looks the same as "nothing found", and a report must be able to tell
    "no unencrypted volumes" from "not allowed to list volumes".

    Also swallows Cost Explorer's DataUnavailableException, which it returns
    when there is simply nothing to report (no Savings Plans or reservations,
    or an account too new to have Cost Explorer data) -- that is "no evidence",
    not a failure.
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
                    "DataUnavailableException",
                }:
                    if code in PERMISSION_DENIED_CODES:
                        _record_denied(fn, args, kwargs, exc, code)
                    return default() if callable(default) else default
                raise

        return wrapper

    return decorator


def _record_denied(fn, args, kwargs, exc, code: str) -> None:
    """Note a denied call on the AwsContext among the collector's arguments.
    Helpers that take a bare client have no context to note it on; their
    callers handle the unread value themselves."""
    ctx = next((a for a in (*args, *kwargs.values()) if isinstance(a, AwsContext)), None)
    if ctx is None:
        return
    bound = inspect.signature(fn).bind_partial(*args, **kwargs).arguments
    region = bound.get("region") or bound.get("home_region")
    ctx.record_denied(fn.__name__, region, code, getattr(exc, "operation_name", None))


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
