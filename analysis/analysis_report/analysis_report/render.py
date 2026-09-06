"""Build the self-contained HTML report."""

from __future__ import annotations

import html
import time

from analysis_report.ingest import Source, _is_alert
from analysis_report.md import render as md_render

_CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
 margin:0;background:#f6f7f8;color:#111}
main{max-width:1200px;margin:0 auto;padding:1.5rem}
h1{font-size:1.5rem;margin:.2rem 0}
h2{font-size:1.15rem;border-bottom:2px solid #d0d3d7;padding-bottom:.2rem;
 margin-top:2rem}
.meta{background:#fff;border:1px solid #d9dce0;border-radius:8px;padding:1rem;
 margin:1rem 0}
.meta table{border-collapse:collapse} .meta th{text-align:left;padding-right:1rem;
 vertical-align:top;color:#555;font-weight:600}
.summary{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}
.card{background:#fff;border:1px solid #d9dce0;border-radius:8px;padding:.7rem 1rem;
 min-width:120px}
.card .n{font-size:1.4rem;font-weight:700} .card.alert .n{color:#b00020}
details{background:#fff;border:1px solid #d9dce0;border-radius:8px;margin:.7rem 0;
 padding:.3rem .8rem}
summary{cursor:pointer;font-weight:600;padding:.4rem 0}
summary .tool{color:#555;font-weight:400}
table.data{border-collapse:collapse;width:100%;font-size:12.5px;display:block;
 overflow-x:auto}
table.data th,table.data td{border:1px solid #e0e3e7;padding:.25rem .5rem;
 text-align:left;white-space:nowrap;max-width:520px;overflow:hidden;
 text-overflow:ellipsis}
table.data thead th{position:sticky;top:0;background:#eef0f2}
tr.alert{background:#fff2f2}
.notes{background:#fff;border:1px solid #d9dce0;border-radius:8px;padding:1rem}
footer{color:#777;margin:2rem 0 1rem;font-size:12px}
code{background:#eceef0;padding:.1em .3em;border-radius:3px}
pre{background:#1e1e1e;color:#e6e6e6;padding:.8rem;border-radius:6px;overflow-x:auto}
@media(prefers-color-scheme:dark){
 body{background:#161719;color:#e6e6e6}
 .meta,.card,details,.notes{background:#1f2123;border-color:#33363a}
 table.data th,table.data td{border-color:#33363a}
 table.data thead th{background:#26282b} tr.alert{background:#3a2020}
 summary .tool{color:#aaa} h2{border-color:#33363a}}
"""


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return html.escape(s if len(s) <= 600 else s[:600] + " …")


def _table(src: Source, max_rows: int) -> str:
    if not src.rows:
        return "<p><em>no rows</em></p>"
    cols = src.columns or list(src.rows[0].keys())
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = []
    for r in src.rows[:max_rows]:
        cls = ' class="alert"' if _is_alert(r) else ""
        body.append(f"<tr{cls}>" + "".join(
            f"<td>{_cell(r.get(c))}</td>" for c in cols) + "</tr>")
    more = (f"<p><em>+ {src.row_count - max_rows} more rows "
            f"(see the source file)</em></p>" if src.row_count > max_rows
            else "")
    return (f'<table class="data"><thead><tr>{head}</tr></thead>'
            f"<tbody>{''.join(body)}</tbody></table>{more}")


def build_html(*, title: str, meta: dict, sources: list[Source],
               notes_md: str = "", max_rows: int = 500) -> str:
    e = html.escape
    total_rows = sum(s.row_count for s in sources)
    total_alerts = sum(s.alert_rows for s in sources)
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    meta_rows = "".join(
        f"<tr><th>{e(k.replace('_', ' ').title())}</th><td>{e(str(v))}</td></tr>"
        for k, v in meta.items() if v)
    cards = (
        f'<div class="card"><div class="n">{len(sources)}</div>sources</div>'
        f'<div class="card"><div class="n">{total_rows}</div>rows</div>'
        f'<div class="card alert"><div class="n">{total_alerts}</div>'
        f"alert rows</div>")

    sections = []
    for s in sources:
        badge = (f' &nbsp;<span style="color:#b00020">▲ {s.alert_rows}</span>'
                 if s.alert_rows else "")
        sections.append(
            f"<details{' open' if s.alert_rows else ''}><summary>{e(s.name)} "
            f"<span class=tool>· {e(s.tool)} · {s.row_count} rows{badge}</span>"
            f"</summary>{_table(s, max_rows)}</details>")

    manifest = "".join(
        f"<tr><td>{e(s.name)}</td><td class=mono>{s.sha256}</td>"
        f"<td>{s.row_count}</td><td>{e(s.tool)}</td></tr>" for s in sources)

    notes_html = (f'<h2>Findings &amp; notes</h2><div class="notes">'
                  f"{md_render(notes_md)}</div>" if notes_md.strip() else "")

    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{_CSS}</style></head><body><main>
<h1>{e(title)}</h1>
<p style="color:#777">generated {generated} by analysis_report</p>
<div class="meta"><table>{meta_rows or '<tr><td>(no case metadata)</td></tr>'}
</table></div>
<div class="summary">{cards}</div>
{notes_html}
<h2>Sources</h2>
{''.join(sections)}
<h2>Input manifest (SHA-256)</h2>
<table class="data"><thead><tr><th>file</th><th>sha256</th><th>rows</th>
<th>tool</th></tr></thead><tbody>{manifest}</tbody></table>
<footer>analysis_report — Forensics Tools</footer>
</main></body></html>"""


def build_bundle(*, title: str, meta: dict, sources: list[Source],
                 notes_md: str) -> dict:
    return {
        "tool": "analysis_report",
        "title": title,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metadata": meta,
        "notes_markdown": notes_md,
        "sources": [{
            "name": s.name, "path": s.path, "tool": s.tool, "kind": s.kind,
            "sha256": s.sha256, "rows": s.row_count, "alert_rows": s.alert_rows,
            "columns": s.columns, "data": s.rows,
        } for s in sources],
        "summary": {
            "sources": len(sources),
            "rows": sum(s.row_count for s in sources),
            "alert_rows": sum(s.alert_rows for s in sources),
        },
    }
