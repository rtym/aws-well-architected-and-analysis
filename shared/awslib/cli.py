"""Common argparse scaffolding shared by every skill's CLI script, so
--profile/--region/--output-dir/--formats behave identically everywhere."""
from __future__ import annotations

import argparse

from .session import AwsContext


def base_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--profile", default=None, help="AWS CLI profile name (default: AWS default chain)")
    parser.add_argument("--region", default=None, help="Primary AWS region (default: session/CLI default region)")
    parser.add_argument(
        "--output-dir", default="reports/output", help="Directory for generated report files (default: reports/output)"
    )
    parser.add_argument(
        "--formats",
        default="md,html,pdf",
        help="Comma-separated report formats to render: md,html,pdf (default: all three)",
    )
    parser.add_argument("--json-out", default=None, help="Optional path to also dump raw evidence as JSON")
    return parser


def formats_tuple(formats_arg: str) -> tuple[str, ...]:
    return tuple(f.strip() for f in formats_arg.split(",") if f.strip())


def make_context(args) -> AwsContext:
    return AwsContext(profile=args.profile, region=args.region)


def resolve_regions(ctx: AwsContext, args) -> list[str]:
    """Shared --region / --regions / --all-regions resolution for
    multi-region scripts. Single-region scripts just use args.region directly.

    Falls back to the session/default region whenever nothing usable comes
    out the other end -- including a `--regions` value that's non-empty but
    parses down to nothing (e.g. " , "), which previously returned `[]` and
    made callers crash on an unguarded `regions[0]`.
    """
    if getattr(args, "all_regions", False):
        return ctx.enabled_regions()
    regions_arg = getattr(args, "regions", None) or args.region
    if regions_arg:
        parsed = [r.strip() for r in regions_arg.split(",") if r.strip()]
        if parsed:
            return parsed
    return [ctx.session.region_name or "us-east-1"]
