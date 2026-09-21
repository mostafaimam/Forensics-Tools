"""Tie header parsing, tar-member listing, and row shaping together."""

from __future__ import annotations

from dataclasses import dataclass, field

from mobile_android.abformat import AbFormatError
from mobile_android.extract import EncryptedBackupError, list_entries

COLUMNS = ["package", "category", "path", "entry_type", "size", "mtime",
          "mode_octal", "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    header: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def collect(ab_path: str) -> Result:
    res = Result()
    try:
        entries, header = list_entries(ab_path)
    except EncryptedBackupError as e:
        res.warnings.append(str(e))
        return res
    except (AbFormatError, OSError) as e:
        res.warnings.append(f"{ab_path}: {e}")
        return res

    res.header = {"version": header.version, "compressed": header.compressed,
                 "encryption": header.encryption}
    for e in entries:
        res.rows.append({
            "package": e.package, "category": e.category, "path": e.path,
            "entry_type": e.entry_type, "size": e.size, "mtime": e.mtime,
            "mode_octal": oct(e.mode), "source": ab_path,
        })
    if not res.rows:
        res.warnings.append("no entries found in the backup archive")
    return res
