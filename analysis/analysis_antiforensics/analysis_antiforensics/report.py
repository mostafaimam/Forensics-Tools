"""Self-contained HTML report."""

from __future__ import annotations

import html

_SEV_COLOR = {"high": "#c0392b", "medium": "#d68910", "low": "#2874a6",
              "info": "#566573"}


def html_report(findings, datasets) -> str:
    e = html.escape
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    chips = " ".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}">{n} {s}</span>'
        for s, n in sorted(counts.items(),
                           key=lambda kv: -{"high": 3, "medium": 2, "low": 1,
                                            "info": 0}[kv[0]]))
    rows = []
    for f in findings:
        ev = "".join(f"<li><code>{e(x)}</code></li>" for x in f.evidence[:8])
        rows.append(f"""
        <div class="finding">
          <div class="fh"><span class="sev" style="background:
            {_SEV_COLOR[f.severity]}">{f.severity.upper()}</span>
            <b>{e(f.title)}</b>
            <span class="src">{e(f.tool)}</span></div>
          <div class="fd">{e(f.detail)}</div>
          {"<div class='ft'>" + e("; ".join(f.times)) + "</div>" if
           any(f.times) else ""}
          {"<ul class='ev'>" + ev + "</ul>" if ev else ""}
        </div>""")
    src = "".join(
        f"<li>{e(d.path)} &mdash; detected as <b>{e(d.tool)}</b> "
        f"({len(d.rows)} rows)</li>" for d in datasets)
    return f"""<!doctype html><meta charset=utf-8>
<title>analysis_antiforensics report</title>
<style>
 body{{font:14px/1.5 system-ui,Segoe UI,Arial;margin:0;background:#f4f6f8;
   color:#1c2833}}
 header{{background:#1c2833;color:#fff;padding:18px 28px}}
 h1{{margin:0;font-size:20px}} main{{max-width:960px;margin:20px auto;
   padding:0 20px}}
 .chip,.sev{{color:#fff;border-radius:10px;padding:2px 9px;font-size:12px;
   font-weight:600}}
 .finding{{background:#fff;border:1px solid #d6dbdf;border-radius:8px;
   padding:12px 14px;margin:10px 0}}
 .fh{{display:flex;gap:10px;align-items:center}}
 .src{{margin-left:auto;color:#85929e;font-size:12px}}
 .fd{{margin:6px 0}} .ft{{color:#85929e;font-size:12px}}
 ul.ev{{margin:6px 0 0;font-size:12px;color:#566573}}
 code{{background:#eef1f3;padding:1px 4px;border-radius:3px;word-break:break-all}}
 .none{{background:#fff;border:1px dashed #d6dbdf;border-radius:8px;
   padding:20px;text-align:center;color:#566573}}
</style>
<header><h1>Anti-forensics &amp; tampering indicators</h1>
<div style="margin-top:8px">{chips or
  '<span class=chip style="background:#27ae60">no indicators</span>'}</div>
</header>
<main>
 {"".join(rows) or "<div class=none>No anti-forensic indicators found in "
  "the supplied datasets.</div>"}
 <h3>Sources</h3><ul>{src}</ul>
</main>"""
