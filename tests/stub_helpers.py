"""Helpers for stubbing boto3 clients not covered (or only partially covered)
by moto: Security Hub findings, GuardDuty findings, Access Analyzer, Config,
Well-Architected Tool, and several Cost Explorer recommendation endpoints.
"""
from __future__ import annotations

from botocore.stub import Stubber


def install_stub(ctx, service: str, region: str | None = None):
    """Create a real boto3 client, wrap it in a Stubber, and pre-seed the
    AwsContext client cache so collectors under test transparently get the
    stubbed client via ctx.client(service, ...)."""
    client = ctx.session.client(service, region_name=region or ctx.region)
    stubber = Stubber(client)
    stubber.activate()
    ctx._client_cache[(service, region or ctx.region)] = client
    return client, stubber
