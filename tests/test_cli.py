import argparse


from shared.awslib.cli import base_parser, formats_tuple, make_context, resolve_regions
from shared.awslib.session import AwsContext


def test_formats_tuple_splits_and_strips():
    assert formats_tuple("md,html,pdf") == ("md", "html", "pdf")
    assert formats_tuple(" md , html ") == ("md", "html")
    assert formats_tuple("md,,html") == ("md", "html")


def test_formats_tuple_empty_string_returns_empty_tuple():
    assert formats_tuple("") == ()


def test_make_context_uses_profile_and_region_from_args():
    args = argparse.Namespace(profile="my-profile", region="eu-west-1")
    ctx = make_context(args)
    assert isinstance(ctx, AwsContext)
    assert ctx.profile == "my-profile"
    assert ctx.region == "eu-west-1"


def test_base_parser_defaults():
    parser = base_parser("test")
    args = parser.parse_args([])
    assert args.profile is None
    assert args.region is None
    assert args.output_dir == "reports/output"
    assert args.formats == "md,html,pdf"
    assert args.json_out is None


def test_resolve_regions_all_regions_flag(monkeypatch):
    ctx = AwsContext(region="us-east-1")
    monkeypatch.setattr(ctx, "enabled_regions", lambda: ["eu-west-1", "us-east-1"])
    args = argparse.Namespace(all_regions=True, regions=None, region="us-east-1")

    assert resolve_regions(ctx, args) == ["eu-west-1", "us-east-1"]


def test_resolve_regions_comma_separated_list():
    ctx = AwsContext(region="us-east-1")
    args = argparse.Namespace(all_regions=False, regions="eu-west-1, ap-southeast-2", region="us-east-1")

    assert resolve_regions(ctx, args) == ["eu-west-1", "ap-southeast-2"]


def test_resolve_regions_falls_back_to_single_region_when_regions_absent():
    ctx = AwsContext(region="us-east-1")
    args = argparse.Namespace(all_regions=False, regions=None, region="ap-southeast-2")

    assert resolve_regions(ctx, args) == ["ap-southeast-2"]


def test_resolve_regions_falls_back_to_session_default_when_nothing_set():
    ctx = AwsContext()  # no region set at all
    args = argparse.Namespace(all_regions=False, regions=None, region=None)

    result = resolve_regions(ctx, args)
    assert result == [ctx.session.region_name or "us-east-1"]
    assert len(result) == 1


def test_resolve_regions_whitespace_only_regions_arg_falls_back_instead_of_empty_list():
    """Regression test: a --regions value that's non-empty but parses down
    to nothing (all commas/whitespace) used to return [] silently, which
    made callers doing regions[0] crash with IndexError."""
    ctx = AwsContext(region="us-east-1")
    args = argparse.Namespace(all_regions=False, regions=" , ,  ", region="us-east-1")

    result = resolve_regions(ctx, args)
    assert result == ["us-east-1"]
    assert len(result) > 0


def test_resolve_regions_no_all_regions_attribute_does_not_crash():
    """Single-region scripts' argparse.Namespace has no `all_regions`/
    `regions` attributes at all -- resolve_regions must tolerate that via
    getattr defaults rather than raising AttributeError."""
    ctx = AwsContext(region="us-east-1")
    args = argparse.Namespace(region="eu-central-1")

    assert resolve_regions(ctx, args) == ["eu-central-1"]
