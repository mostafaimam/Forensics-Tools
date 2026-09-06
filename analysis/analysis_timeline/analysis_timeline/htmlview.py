"""Generate a single self-contained HTML timeline viewer.

No server, no external resources - the events are inlined as JSON and the page
provides column sorting, full-text and date-range filtering, type/tool facets,
per-row tagging (persisted in the browser) and CSV export of the current view.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from analysis_timeline.model import Event

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root{color-scheme:light dark}
  *{box-sizing:border-box}
  body{margin:0;font:13px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:#f6f7f9;color:#14181f}
  @media (prefers-color-scheme:dark){body{background:#14181f;color:#e6e9ee}}
  header{position:sticky;top:0;z-index:5;padding:10px 14px;
         background:#1f6feb;color:#fff;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  header h1{font-size:15px;margin:0;font-weight:600}
  header .meta{opacity:.85;font-size:12px}
  .controls{display:flex;gap:8px;flex-wrap:wrap;padding:10px 14px;
            border-bottom:1px solid #0002;background:#fff}
  @media (prefers-color-scheme:dark){.controls{background:#1b2029;border-color:#fff2}}
  input,select,button{font:inherit;padding:5px 8px;border-radius:6px;
        border:1px solid #8886;background:transparent;color:inherit}
  button{cursor:pointer}
  .wrap{overflow:auto;max-height:calc(100vh - 150px)}
  table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
  th,td{text-align:left;padding:5px 9px;border-bottom:1px solid #8883;
        vertical-align:top;white-space:nowrap}
  td.desc{white-space:normal;min-width:340px}
  th{position:sticky;top:0;background:#eceff3;cursor:pointer;user-select:none}
  @media (prefers-color-scheme:dark){th{background:#232936}}
  tr:hover td{background:#1f6feb14}
  tr.tagged td{background:#f5b91133}
  .pill{display:inline-block;padding:1px 7px;border-radius:999px;background:#8882;font-size:11px}
  .tagbtn{border:none;background:none;cursor:pointer;font-size:14px;opacity:.4}
  tr.tagged .tagbtn{opacity:1}
  footer{padding:8px 14px;font-size:12px;opacity:.7}
</style></head><body>
<header>
  <h1>__TITLE__</h1>
  <span class="meta" id="count"></span>
</header>
<div class="controls">
  <input id="q" placeholder="filter text (regex ok)" size="28">
  <input id="from" type="datetime-local" title="from">
  <input id="to" type="datetime-local" title="to">
  <select id="type"><option value="">any type</option></select>
  <select id="tool"><option value="">any tool</option></select>
  <label><input type="checkbox" id="onlytag"> tagged only</label>
  <button id="export">export view CSV</button>
  <button id="cleartags">clear tags</button>
</div>
<div class="wrap"><table id="t"><thead><tr>
  <th data-k="tag"></th>
  <th data-k="timestamp_utc">timestamp (UTC)</th>
  <th data-k="timestamp_type">type</th>
  <th data-k="tool">tool</th>
  <th data-k="host">host</th>
  <th data-k="user">user</th>
  <th data-k="description">description</th>
  <th data-k="source_file">source</th>
</tr></thead><tbody id="b"></tbody></table></div>
<footer>analysis_timeline &middot; __N__ events &middot; tags stored in this browser only</footer>
<script>
const DATA = __DATA__;
const KEY = "analysis_timeline:" + (location.pathname||"tl");
let tags = {};
try{ tags = JSON.parse(localStorage.getItem(KEY)||"{}"); }catch(e){}
let sortK = "timestamp_utc", sortAsc = true;

const el = id => document.getElementById(id);
const rid = r => r.timestamp_utc+"|"+r.timestamp_type+"|"+r.tool+"|"+r.description;

function facet(id, key){
  const s = el(id), seen=[...new Set(DATA.map(r=>r[key]).filter(Boolean))].sort();
  for(const v of seen){ const o=document.createElement("option"); o.value=o.textContent=v; s.appendChild(o); }
}
facet("type","timestamp_type"); facet("tool","tool");

function view(){
  let rx=null; const qv=el("q").value.trim();
  if(qv){ try{ rx=new RegExp(qv,"i"); }catch(e){ rx=new RegExp(qv.replace(/[.*+?^${}()|[\\]\\\\]/g,"\\\\$&"),"i"); } }
  const f=el("from").value, t=el("to").value;
  const ty=el("type").value, tl=el("tool").value, ot=el("onlytag").checked;
  let rows=DATA.filter(r=>{
    if(ty && r.timestamp_type!==ty) return false;
    if(tl && r.tool!==tl) return false;
    if(f && r.timestamp_utc < f.replace("T"," ")) return false;
    if(t && r.timestamp_utc.slice(0,16) > t) return false;
    if(ot && !tags[rid(r)]) return false;
    if(rx && !rx.test(r.description) && !rx.test(r.tool) && !rx.test(r.source_file)
       && !rx.test(JSON.stringify(r.extra||""))) return false;
    return true;
  });
  rows.sort((a,b)=>{ const x=(a[sortK]||""),y=(b[sortK]||"");
    return (x<y?-1:x>y?1:0)*(sortAsc?1:-1); });
  return rows;
}

function render(){
  const rows=view(); const b=el("b"); b.textContent="";
  const frag=document.createDocumentFragment();
  for(const r of rows){
    const tr=document.createElement("tr"); const id=rid(r);
    if(tags[id]) tr.className="tagged";
    const cells=[
      `<button class="tagbtn" data-id="${encodeURIComponent(id)}">\u2605</button>`,
      esc(r.timestamp_utc), `<span class="pill">${esc(r.timestamp_type)}</span>`,
      esc(r.tool), esc(r.host), esc(r.user),
      `<span class="desc">${esc(r.description)}</span>`, esc(r.source_file),
    ];
    tr.innerHTML = cells.map((c,i)=>`<td class="${i===6?'desc':''}">${c}</td>`).join("");
    frag.appendChild(tr);
  }
  b.appendChild(frag);
  el("count").textContent = rows.length+" / "+DATA.length+" events";
}
function esc(s){ return String(s==null?"":s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }

document.addEventListener("click",e=>{
  const tb=e.target.closest(".tagbtn");
  if(tb){ const id=decodeURIComponent(tb.dataset.id);
    if(tags[id]) delete tags[id]; else tags[id]=1;
    localStorage.setItem(KEY,JSON.stringify(tags)); render(); }
});
document.querySelectorAll("th[data-k]").forEach(th=>th.onclick=()=>{
  const k=th.dataset.k; if(!k) return;
  if(sortK===k) sortAsc=!sortAsc; else { sortK=k; sortAsc=true; } render();
});
["q","from","to","type","tool","onlytag"].forEach(id=>{
  el(id).addEventListener("input",render);
});
el("cleartags").onclick=()=>{ tags={}; localStorage.removeItem(KEY); render(); };
el("export").onclick=()=>{
  const rows=view();
  const cols=["timestamp_utc","timestamp_type","tool","artifact","host","user","description","source_file"];
  const q=s=>'"'+String(s==null?"":s).replace(/"/g,'""')+'"';
  const csv=[cols.join(",")].concat(rows.map(r=>cols.map(c=>q(r[c])).join(","))).join("\\r\\n");
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob(["\\ufeff"+csv],{type:"text/csv"}));
  a.download="timeline_view.csv"; a.click();
};
render();
</script></body></html>
"""


def write_html(events: list[Event], path: Path, title: str = "Timeline") -> None:
    records = [e.as_json() for e in events]
    payload = json.dumps(records, default=str, ensure_ascii=False)
    page = (
        _PAGE.replace("__DATA__", payload)
        .replace("__TITLE__", html.escape(title))
        .replace("__N__", str(len(records)))
    )
    path.write_text(page, encoding="utf-8")
