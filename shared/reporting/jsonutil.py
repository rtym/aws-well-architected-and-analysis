"""JSON helpers for serializing raw boto3 responses (datetimes, Decimals)."""
from __future__ import annotations

import datetime
import decimal
import json
import os


def default(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)


def dumps(obj, **kwargs) -> str:
    return json.dumps(obj, default=default, indent=kwargs.pop("indent", 2), **kwargs)


def write(obj, path: str) -> None:
    """Write `obj` as JSON, creating the parent directory first. Scripts
    write the evidence before the report (which creates --output-dir), so
    the documented `--json-out reports/output/...` failed on a first run,
    after the whole scan."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w") as fh:
        fh.write(dumps(obj))
