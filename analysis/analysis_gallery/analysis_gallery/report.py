"""Self-contained HTML contact sheet."""

from __future__ import annotations

import datetime as _dt
import html
from pathlib import Path


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _card(mf, box: int, data_attrs: str = "") -> str:
    uri = mf.thumb_datauri(box)
    if uri:
        img = f'<img loading="lazy" src="{uri}" alt="">'
    else:
        img = f'<div class="noimg">{_esc(mf.format)}</div>'
    meta = []
    if mf.width and mf.height:
        meta.append(f"{mf.width}&times;{mf.height}")
    if mf.megapixels and mf.megapixels >= 1.0:
        meta.append(f"{mf.megapixels:g} MP")
    if mf.duration_s:
        meta.append(f"{mf.duration_s:g}s")
    dt = mf.datetime_original or mf.datetime_modified
    rows = []
    if dt:
        rows.append(("taken", dt))
    if mf.make or mf.model:
        rows.append(("camera", f"{mf.make} {mf.model}".strip()))
    if mf.lens:
        rows.append(("lens", mf.lens))
    shot = " ".join(x for x in (mf.focal_length, mf.f_number, mf.exposure,
                                mf.iso) if x)
    if shot:
        rows.append(("settings", shot))
    if mf.software:
        rows.append(("software", mf.software))
    if mf.has_gps:
        rows.append(("gps", f'<a href="{_esc(mf.maps_url)}" target="_blank" '
                     f'rel="noopener">{mf.gps_lat}, {mf.gps_lon}</a>'))
    if mf.artist:
        rows.append(("artist", mf.artist))
    if mf.phash:
        rows.append(("phash", f'<span class="mono">{_esc(mf.phash)}</span>'))
    if mf.notes:
        rows.append(("notes", mf.notes))
    if mf.sha256:
        rows.append(("sha256", f'<span class="mono">{_esc(mf.sha256[:16])}'
                     f'&hellip;</span>'))

    _raw = ("gps", "sha256", "phash")
    body = "".join(
        f'<tr><th>{_esc(k)}</th><td>{v if k in _raw else _esc(v)}</td></tr>'
        for k, v in rows)
    badges = ""
    if mf.has_gps:
        badges += '<span class="badge gps">GPS</span>'
    if not mf.has_exif and mf.category == "image":
        badges += '<span class="badge noexif">no EXIF</span>'
    if mf.phash_group:
        badges += f'<span class="badge grp">group {mf.phash_group}</span>'
    return (f'<figure class="card" {data_attrs}>{img}'
            f'<figcaption><div class="name" title="{_esc(mf.path)}">'
            f'{_esc(Path(mf.path).name)}</div>'
            f'<div class="sub">{" &middot; ".join(meta)} {badges}</div>'
            f'<table>{body}</table></figcaption></figure>')


_CSS = """
:root{--bg:#f6f6f4;--fg:#1a1a1a;--card:#fff;--line:#e2e2df;--muted:#6b6b6b;
--accent:#2563eb;--gps:#0a7d33;--warn:#b45309;--grp:#7c3aed}
@media (prefers-color-scheme:dark){:root{--bg:#16171a;--fg:#e6e6e6;
--card:#1e2024;--line:#33363c;--muted:#9aa0a6;--accent:#6ea8fe;--gps:#4ade80;
--warn:#fbbf24;--grp:#c4b5fd}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:16px 20px;border-bottom:1px solid var(--line);position:sticky;
top:0;background:var(--bg);z-index:2}
h1{font-size:16px;margin:0 0 4px}.stats{color:var(--muted);font-size:13px}
.controls{margin-top:10px}.controls input,.controls select{padding:5px 8px;
border:1px solid var(--line);border-radius:6px;background:var(--card);
color:var(--fg)}
main{padding:16px 20px;display:grid;gap:16px;
grid-template-columns:repeat(auto-fill,minmax(240px,1fr))}
.card{margin:0;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden;display:flex;flex-direction:column}
.card img{width:100%;height:180px;object-fit:contain;background:#0002;
display:block}
.noimg{height:180px;display:flex;align-items:center;justify-content:center;
color:var(--muted);background:#0001;font-size:13px}
figcaption{padding:10px 12px}
.name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{color:var(--muted);font-size:12px;margin:2px 0 8px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--muted);font-weight:500;padding:2px 8px 2px 0;
vertical-align:top;white-space:nowrap;width:1%}
td{padding:2px 0;word-break:break-word}
.mono{font-family:ui-monospace,Consolas,monospace}
a{color:var(--accent)}
.badge{display:inline-block;font-size:11px;padding:1px 6px;border-radius:999px;
border:1px solid var(--line);margin-left:4px}
.badge.gps{color:var(--gps);border-color:var(--gps)}
.badge.noexif{color:var(--warn);border-color:var(--warn)}
.badge.grp{color:var(--grp);border-color:var(--grp)}
.groupbar{grid-column:1/-1;font-weight:600;color:var(--grp);
border-top:1px solid var(--line);padding-top:10px}
"""

_JS = """
const q=document.getElementById('q');
const only=document.getElementById('only');
function apply(){const t=(q.value||'').toLowerCase();const o=only.value;
for(const c of document.querySelectorAll('.card')){
const hay=c.dataset.hay;let show=!t||hay.includes(t);
if(show&&o==='gps')show=c.dataset.gps==='1';
if(show&&o==='noexif')show=c.dataset.exif==='0';
if(show&&o==='groups')show=c.dataset.grp!=='0';
c.style.display=show?'':'none';}}
q.addEventListener('input',apply);only.addEventListener('change',apply);
"""


def build_html(rows_files, *, title: str = "analysis_gallery",
               thumb_box: int = 220) -> str:
    files = list(rows_files)
    n_img = sum(1 for f in files if f.category == "image")
    n_vid = sum(1 for f in files if f.category == "video")
    n_gps = sum(1 for f in files if f.has_gps)
    n_grp = len({f.phash_group for f in files if f.phash_group})
    gen = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    cards = []
    last_group = None
    for f in files:
        if f.phash_group != last_group:
            if f.phash_group:
                members = sum(1 for x in files
                              if x.phash_group == f.phash_group)
                cards.append(f'<div class="groupbar">Look-alike group '
                             f'{f.phash_group} &mdash; {members} items</div>')
            last_group = f.phash_group
        hay = " ".join(str(x).lower() for x in
                       (f.path, f.make, f.model, f.software, f.format,
                        f.datetime_original, f.notes))
        attrs = (f'data-hay="{_esc(hay)}" data-gps="{1 if f.has_gps else 0}" '
                 f'data-exif="{1 if f.has_exif else 0}" '
                 f'data-grp="{f.phash_group}"')
        cards.append(_card(f, thumb_box, attrs))
    body = "".join(cards)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title><style>{_CSS}</style></head><body>
<header><h1>{_esc(title)}</h1>
<div class="stats">{len(files)} media files &middot; {n_img} images &middot;
{n_vid} videos &middot; {n_gps} geotagged &middot; {n_grp} look-alike groups
&middot; generated {gen}</div>
<div class="controls">
<input id="q" type="search" placeholder="filter by name / camera / date…">
<select id="only"><option value="">everything</option>
<option value="gps">geotagged only</option>
<option value="noexif">no EXIF only</option>
<option value="groups">grouped only</option></select></div></header>
<main>{body}</main><script>{_JS}</script></body></html>"""


def write_html(files, path: Path, **kw) -> None:
    Path(path).write_text(build_html(files, **kw), encoding="utf-8")
