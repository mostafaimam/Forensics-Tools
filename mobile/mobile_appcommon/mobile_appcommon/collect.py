"""Sniff a blob's format and decode it into flat rows."""

from __future__ import annotations

from dataclasses import dataclass, field

from mobile_appcommon.flatten import flatten_plist, flatten_protobuf
from mobile_appcommon.plists import load as load_plist
from mobile_appcommon.protobuf import decode_top, to_jsonable
from mobile_appcommon.sniff import guess_format

COLUMNS = ["format", "path", "kind", "value", "source"]


@dataclass
class Result:
    fmt: str = ""
    rows: list[dict] = field(default_factory=list)
    tree: object = None
    warnings: list[str] = field(default_factory=list)


def decode_blob(data: bytes, source: str = "") -> Result:
    res = Result()
    fmt = guess_format(data)
    res.fmt = fmt

    if fmt == "plist":
        try:
            value = load_plist(data)
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"plist decode failed: {e}")
            return res
        res.tree = value
        for path, v in flatten_plist(value).items():
            res.rows.append({"format": "plist", "path": path, "kind": "",
                            "value": v, "source": source})

    elif fmt == "sqlite":
        res.warnings.append(
            "this is a SQLite database, not a plist or protobuf blob - "
            "use a SQL-aware tool (windows_sqlmap, or open it directly) "
            "instead")

    elif fmt == "text":
        text = data.decode("utf-8", "replace")
        res.tree = text
        res.rows.append({"format": "text", "path": ".", "kind": "text",
                        "value": text, "source": source})

    else:  # protobuf attempt
        fields = decode_top(data)
        if fields is None:
            res.warnings.append(
                "not recognised as a plist, SQLite database, or valid "
                "protobuf wire-format message")
            return res
        if not fields:
            res.warnings.append("empty input")
            return res
        res.fmt = "protobuf"
        res.tree = to_jsonable(fields)
        for row in flatten_protobuf(fields):
            row["format"] = "protobuf"
            row["source"] = source
            res.rows.append(row)

    return res


def decode_file(path: str) -> Result:
    with open(path, "rb") as fh:
        data = fh.read()
    return decode_blob(data, source=path)
