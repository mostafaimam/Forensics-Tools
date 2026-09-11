"""Graphical viewer for windows_sqlmap."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from windows_sqlmap.guikit import run
    from windows_sqlmap.discover import find
    from windows_sqlmap.analyze import scan
    from windows_sqlmap.maps import builtin_maps

    def load(ps):
        dbs = find([str(p) for p in ps])
        res = scan(dbs, builtin_maps())
        rows = []
        for h in res.hits:
            for r in h.rows:
                row = dict(r); row["_db"] = h.db; row["_map"] = h.map_name
                rows.append(row)
        return rows

    return run("windows_sqlmap - mapped SQLite records", load,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open folder / .db", open_is_dir=True, multi=True)
