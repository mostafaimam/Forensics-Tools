"""Load repositories, extract subscription objects, join filter/consumer."""

from __future__ import annotations

from dataclasses import dataclass, field

from windows_wmi import flags, objects, repo


@dataclass
class Result:
    rows: list = field(default_factory=list)
    repos: int = 0
    filters: int = 0
    consumers: int = 0
    bindings: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def collect(paths) -> Result:
    res = Result()
    all_objs = []
    for path in paths:
        try:
            repos = repo.load(path)
        except Exception as e:  # noqa: BLE001
            res.errors.append(f"{path}: {e}")
            continue
        for rp in repos:
            res.repos += 1
            res.sources.add(rp.source)
            objs = objects.extract(rp)
            all_objs.extend(objs)

    filt_by_name = {o.name: o for o in all_objs
                    if o.otype == "filter" and o.name}
    cons_by_name = {o.name: o for o in all_objs
                    if o.otype == "consumer" and o.name}

    for o in all_objs:
        if o.otype == "binding":
            f = filt_by_name.get(o.filter_ref)
            c = cons_by_name.get(o.consumer_ref)
            if f and not o.query:
                o.query = f.query
            if c:
                o.action = o.action or c.action
                o.action_kind = o.action_kind or c.action_kind
        n, s = flags.classify(o)
        o.notable = n
        row = o.row()
        row["severity"] = s
        res.rows.append(row)
        res.filters += o.otype == "filter"
        res.consumers += o.otype == "consumer"
        res.bindings += o.otype == "binding"

    order = {"binding": 0, "consumer": 1, "filter": 2}
    res.rows.sort(key=lambda r: (order.get(r["type"], 9),
                                 -flags._ORDER.get(r.get("severity"), 0),
                                 r.get("name", "")))
    return res
