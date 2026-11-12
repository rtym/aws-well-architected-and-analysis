"""Common argparse scaffolding shared by every skill's CLI script, so
--profile/--region/--output-dir/--formats behave identically everywhere."""
from __future__ import annotations

import argparse
import sys

from botocore.exceptions import BotoCoreError, ClientError

from .session import PERMISSION_DENIED_CODES, AwsContext


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


def run(main, argv=None) -> int:
    """Run a script's `main`, turning the two failures a user can fix
    themselves into one clear line instead of a traceback: a denied call
    that the scan can't work without, and credentials that didn't resolve
    (no profile, an expired SSO session). Returns 2 for those; anything
    else still raises, because a traceback is the right report for a bug.

    Calls a scan can work without never get here: their collectors are
    wrapped in `ignore_access_denied` and show up in the report's Access
    Gaps section instead.
    """
    try:
        return main(argv)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        if error.get("Code") not in PERMISSION_DENIED_CODES:
            raise
        print(
            f"Stopped: the scan needs {exc.operation_name} and was denied ({error.get('Code')}).\n"
            f"  {error.get('Message') or 'No further detail from AWS.'}\n"
            "  Grant the read-only actions in PERMISSIONS.md at the plugin root, then run it again.",
            file=sys.stderr,
        )
        return 2
    except BotoCoreError as exc:
        # NoCredentialsError, ProfileNotFound, an expired SSO token, no region.
        print(
            f"Stopped: AWS credentials or configuration could not be used ({type(exc).__name__}).\n"
            f"  {exc}\n"
            "  Check --profile and --region, or sign in again (for example `aws sso login`).",
            file=sys.stderr,
        )
        return 2
