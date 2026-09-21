"""Query each store kind into a single unified row schema."""

from __future__ import annotations

from dataclasses import dataclass, field

from browser_shortcuts.dbopen import connect, query, table_columns
from browser_shortcuts.discover import find
from browser_shortcuts.flags import flag
from browser_shortcuts.timeconv import chrome

COLUMNS = ["kind", "browser", "profile", "source", "text", "url", "title",
          "rank", "hits", "misses", "hit_rate", "last_access", "keyword",
          "notable"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _base(store) -> dict:
    return {c: "" for c in COLUMNS} | {
        "kind": store.kind, "browser": store.browser,
        "profile": store.profile, "source": store.path,
    }


def _shortcuts_rows(store) -> list[dict]:
    out = []
    with connect(store.path) as con:
        cols = table_columns(con, "omni_box_shortcuts")
        if not cols:
            return out
        want = [c for c in ("text", "fill_into_edit", "url", "contents",
                            "keyword", "last_access_time",
                            "number_of_hits") if c in cols]
        for r in query(con, f"SELECT {', '.join(want)} "
                       f"FROM omni_box_shortcuts"):
            row = _base(store)
            row["text"] = r["text"] if "text" in want else ""
            row["url"] = (r["url"] if "url" in want else
                         r["fill_into_edit"] if "fill_into_edit" in want
                         else "")
            row["title"] = r["contents"] if "contents" in want else ""
            row["keyword"] = r["keyword"] if "keyword" in want else ""
            if "last_access_time" in want:
                row["last_access"] = chrome(r["last_access_time"])
            if "number_of_hits" in want:
                row["hits"] = r["number_of_hits"]
            row["notable"] = flag(row["url"])
            out.append(row)
    return out


def _top_sites_rows(store) -> list[dict]:
    out = []
    with connect(store.path) as con:
        cols = table_columns(con, "top_sites")
        if not cols:
            return out
        want = [c for c in ("url", "url_rank", "title") if c in cols]
        for r in query(con, f"SELECT {', '.join(want)} FROM top_sites"):
            row = _base(store)
            row["url"] = r["url"] if "url" in want else ""
            row["title"] = r["title"] if "title" in want else ""
            row["rank"] = r["url_rank"] if "url_rank" in want else ""
            row["notable"] = flag(row["url"])
            out.append(row)
    return out


def _predictor_rows(store) -> list[dict]:
    out = []
    with connect(store.path) as con:
        cols = table_columns(con, "network_action_predictor")
        if not cols:
            return out
        want = [c for c in ("user_text", "url", "number_of_hits",
                            "number_of_misses") if c in cols]
        for r in query(con, f"SELECT {', '.join(want)} "
                       f"FROM network_action_predictor"):
            row = _base(store)
            row["text"] = r["user_text"] if "user_text" in want else ""
            row["url"] = r["url"] if "url" in want else ""
            hits = r["number_of_hits"] if "number_of_hits" in want else None
            misses = (r["number_of_misses"] if "number_of_misses" in want
                      else None)
            row["hits"] = hits if hits is not None else ""
            row["misses"] = misses if misses is not None else ""
            if hits is not None and misses is not None and hits + misses:
                row["hit_rate"] = round(hits / (hits + misses), 3)
            row["notable"] = flag(row["url"])
            out.append(row)
    return out


_HANDLERS = {
    "shortcuts": _shortcuts_rows,
    "top_sites": _top_sites_rows,
    "predictor": _predictor_rows,
}


def collect(targets: list[str]) -> Result:
    res = Result()
    stores = []
    for t in targets:
        stores.extend(find(t))
    if not stores:
        res.warnings.append("no Shortcuts / Top Sites / Network Action "
                            "Predictor store found")
        return res
    for store in stores:
        try:
            res.rows.extend(_HANDLERS[store.kind](store))
        except Exception as e:  # noqa: BLE001
            res.warnings.append(f"{store.path}: {e}")
    return res
