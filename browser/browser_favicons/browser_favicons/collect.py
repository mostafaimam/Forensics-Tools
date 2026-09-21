"""Tie discovery + per-browser readers + the history cross-check together."""

from __future__ import annotations

from dataclasses import dataclass, field

from browser_favicons import chromium, firefox
from browser_favicons.discover import find
from browser_favicons.history_check import load_history_urls

COLUMNS = ["browser", "profile", "page_url", "icon_url", "icon_type",
          "width", "height", "last_updated", "cleared_from_history",
          "source", "image_bytes"]

_READERS = {"chromium": chromium.read, "firefox": firefox.read}


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    images: dict[int, bytes] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def collect(targets: list[str], *, history_path: str | None = None) -> Result:
    res = Result()
    history_urls = None
    if history_path:
        try:
            history_urls = load_history_urls(history_path)
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"could not read --history {history_path}: {e}")
        if history_urls is None:
            res.warnings.append(f"--history {history_path} has neither a "
                                "'urls' nor a 'moz_places' table")

    stores = []
    for t in targets:
        stores.extend(find(t))
    if not stores:
        res.warnings.append("no Favicons / favicons.sqlite store found")
        return res

    for store in stores:
        try:
            rows = _READERS[store.family](store.path)
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{store.path}: {e}")
            continue
        for r in rows:
            image = r.pop("image_data")
            row = dict(r)
            row["profile"] = store.profile
            row["source"] = store.path
            row["image_bytes"] = len(image) if image else 0
            if history_urls is not None:
                row["cleared_from_history"] = row["page_url"] not in \
                    history_urls
            else:
                row["cleared_from_history"] = ""
            row_index = len(res.rows)
            res.rows.append(row)
            if image:
                res.images[row_index] = image
    return res
