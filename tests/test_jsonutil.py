import datetime
import decimal
import json
import os

from shared.reporting import jsonutil


def test_dumps_serializes_datetime_as_isoformat():
    obj = {"CreatedAt": datetime.datetime(2024, 1, 1, 12, 30, 0)}
    result = json.loads(jsonutil.dumps(obj))
    assert result["CreatedAt"] == "2024-01-01T12:30:00"


def test_dumps_serializes_date_as_isoformat():
    obj = {"Day": datetime.date(2024, 6, 15)}
    result = json.loads(jsonutil.dumps(obj))
    assert result["Day"] == "2024-06-15"


def test_dumps_serializes_decimal_as_float():
    obj = {"Value": decimal.Decimal("42.5")}
    result = json.loads(jsonutil.dumps(obj))
    assert result["Value"] == 42.5


def test_dumps_serializes_bytes_as_decoded_string():
    obj = {"Content": b"hello world"}
    result = json.loads(jsonutil.dumps(obj))
    assert result["Content"] == "hello world"


def test_dumps_falls_back_to_str_for_unknown_types():
    class Weird:
        def __str__(self):
            return "weird-repr"

    obj = {"Thing": Weird()}
    result = json.loads(jsonutil.dumps(obj))
    assert result["Thing"] == "weird-repr"


def test_dumps_handles_nested_structures_with_mixed_types():
    obj = {
        "Trails": [
            {"Name": "t1", "CreatedAt": datetime.datetime(2024, 1, 1)},
            {"Name": "t2", "Cost": decimal.Decimal("10.0")},
        ]
    }
    result = json.loads(jsonutil.dumps(obj))
    assert result["Trails"][0]["CreatedAt"] == "2024-01-01T00:00:00"
    assert result["Trails"][1]["Cost"] == 10.0


def test_write_creates_valid_json_file(tmp_path):
    obj = {"Region": "us-east-1", "Timestamp": datetime.datetime(2024, 1, 1)}
    path = os.path.join(tmp_path, "evidence.json")

    jsonutil.write(obj, path)

    with open(path) as fh:
        loaded = json.load(fh)
    assert loaded["Region"] == "us-east-1"
    assert loaded["Timestamp"] == "2024-01-01T00:00:00"
