"""Self-contained interactive HTML review page."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

_CSS = """
:root{--bg:#f6f6f4;--fg:#1b1b1b;--pane:#fff;--line:#e0e0dd;--muted:#6b6b6b;
--accent:#2563eb;--hi:#fff3cd;--rev:#eef6ee}
@media(prefers-color-scheme:dark){:root{--bg:#15171a;--fg:#e6e6e6;--pane:#1e2024;
--line:#33363c;--muted:#9aa0a6;--accent:#6ea8fe;--hi:#3a3320;--rev:#20281f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.4 system-ui,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;background:var(--bg);
border-bottom:1px solid var(--line);padding:8px 12px}
h1{font-size:14px;margin:0 0 6px}
.bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
input,select,button{font:inherit;padding:4px 7px;border:1px solid var(--line);
border-radius:6px;background:var(--pane);color:var(--fg)}
button{cursor:pointer}
.count{color:var(--muted);margin-left:auto}
.wrap{overflow:auto;max-height:calc(100vh - 96px)}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid var(--line);padding:3px 8px;text-align:left;
vertical-align:top;white-space:nowrap;max-width:520px;overflow:hidden;
text-overflow:ellipsis}
thead th{position:sticky;top:0;background:var(--pane);cursor:pointer;
user-select:none}
thead tr.filters th{position:sticky;top:26px;background:var(--pane)}
thead tr.filters input{width:100%;padding:2px 4px;font-size:12px}
tbody tr:hover{background:#00000008}
tr.reviewed td{background:var(--rev);color:var(--muted)}
tr.tagged td:first-child{border-left:3px solid var(--tc,#888)}
.tagcell,.notecell{white-space:normal;min-width:120px}
.tag{display:inline-block;font-size:11px;padding:0 6px;border-radius:999px;
color:#fff;margin:1px}
.note{width:100%;border:1px dashed var(--line);background:transparent;
color:var(--fg);font-size:12px;padding:1px 3px}
.chk{cursor:pointer}
.hidden{display:none}
mark{background:var(--hi);color:inherit}
.rulebox{font-size:12px;color:var(--muted)}
"""

_JS = r"""
const DATA = __DATA__, COLS = __COLS__, RULES = __RULES__;
let review = __REVIEW__;
let sort = [], colFilter = {}, hideReviewed = false, tagFilter = "";
const PALETTE=["#d33","#e67e22","#2ca","#39c","#7c3aed","#c2185b","#0a7d33",
"#8d6e63"];
function colorFor(t){if(!review.tag_colors[t]){
 review.tag_colors[t]=PALETTE[Object.keys(review.tag_colors).length%PALETTE.length];}
 return review.tag_colors[t];}
const $=s=>document.querySelector(s);
function esc(s){return (s+"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function hl(s){const q=$("#q").value.trim();if(!q)return esc(s);
 return esc(s).replace(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'ig'),
  m=>'<mark>'+m+'</mark>');}
function passes(r){
 const q=$("#q").value.trim().toLowerCase();
 if(q && !COLS.some(c=>(r[c]+"").toLowerCase().includes(q))) return false;
 for(const c in colFilter){const f=colFilter[c].toLowerCase();
   if(f && !(r[c]+"").toLowerCase().includes(f)) return false;}
 if(hideReviewed && review.reviewed.includes(r._id)) return false;
 if(tagFilter){const t=(review.tags[r._id]||[]);
   if(tagFilter==="__none"){if(t.length)return false;}
   else if(!t.includes(tagFilter))return false;}
 return true;
}
function ruleColor(r){for(const rule of RULES){
 try{if(new RegExp(rule.match,"i").test(r[rule.col]||"")) return rule.color;}
 catch(e){}}return "";}
function cmp(a,b){const ta=Date.parse(a),tb=Date.parse(b);
 if(!isNaN(ta)&&!isNaN(tb))return ta-tb;
 const na=parseFloat((a+"").replace(/,/g,'')),nb=parseFloat((b+"").replace(/,/g,''));
 if(!isNaN(na)&&!isNaN(nb))return na-nb;
 return (a+"").localeCompare(b+"");}
function render(){
 let rows=DATA.filter(passes);
 for(const s of [...sort].reverse())
   rows.sort((x,y)=>(s.dir==="d"?-1:1)*cmp(x[s.col],y[s.col]));
 const tb=$("#body");tb.innerHTML="";
 const frag=document.createDocumentFragment();
 for(const r of rows){
  const tr=document.createElement("tr");
  const tags=review.tags[r._id]||[];
  if(review.reviewed.includes(r._id))tr.className="reviewed";
  if(tags.length){tr.classList.add("tagged");tr.style.setProperty("--tc",colorFor(tags[0]));}
  const rc=ruleColor(r);if(rc)tr.style.background=rc;
  let cells=`<td class="chk" title="mark reviewed">${review.reviewed.includes(r._id)?"✓":"☐"}</td>`;
  for(const c of COLS)cells+=`<td title="${esc(r[c])}">${hl(r[c])}</td>`;
  cells+=`<td class="tagcell">${tags.map(t=>`<span class="tag" style="background:${colorFor(t)}">${esc(t)}</span>`).join("")}<button data-act="tag">+</button></td>`;
  cells+=`<td class="notecell"><input class="note" value="${esc(review.notes[r._id]||"")}" data-id="${r._id}"></td>`;
  tr.innerHTML=cells;tr.dataset.id=r._id;frag.appendChild(tr);
 }
 tb.appendChild(frag);
 $("#count").textContent=`${rows.length} / ${DATA.length} rows`;
 rebuildTagFilter();
}
function rebuildTagFilter(){const sel=$("#tagf");const cur=sel.value;
 sel.innerHTML='<option value="">any tag</option><option value="__none">untagged</option>'
  + review_allTags().map(t=>`<option>${esc(t)}</option>`).join("");
 sel.value=cur;}
function review_allTags(){const s=new Set();
 for(const k in review.tags)review.tags[k].forEach(t=>s.add(t));
 return [...s].sort();}
$("#body").addEventListener("click",e=>{
 const tr=e.target.closest("tr");if(!tr)return;const id=tr.dataset.id;
 if(e.target.classList.contains("chk")){
   const i=review.reviewed.indexOf(id);
   if(i<0)review.reviewed.push(id);else review.reviewed.splice(i,1);render();}
 else if(e.target.dataset.act==="tag"){
   const t=prompt("tag (comma-separated to add several):");if(!t)return;
   review.tags[id]=[...new Set([...(review.tags[id]||[]),
     ...t.split(",").map(s=>s.trim()).filter(Boolean)])];render();}
});
$("#body").addEventListener("dblclick",e=>{
 const tr=e.target.closest("tr");if(!tr)return;const id=tr.dataset.id;
 if(e.target.tagName==="TD"&&!e.target.classList.contains("tagcell")){
   review.tags[id]=[];render();}
});
$("#body").addEventListener("change",e=>{
 if(e.target.classList.contains("note"))
   review.notes[e.target.dataset.id]=e.target.value;});
document.querySelectorAll("thead .h").forEach(th=>th.addEventListener("click",()=>{
 const c=th.dataset.col;const cur=sort.find(s=>s.col===c);
 if(cur)cur.dir=cur.dir==="a"?"d":(sort=sort.filter(s=>s!==cur),null);
 else sort.unshift({col:c,dir:"a"});render();}));
document.querySelectorAll("thead .filters input").forEach(inp=>
 inp.addEventListener("input",()=>{colFilter[inp.dataset.col]=inp.value;render();}));
$("#q").addEventListener("input",render);
$("#hr").addEventListener("change",e=>{hideReviewed=e.target.checked;render();});
$("#tagf").addEventListener("change",e=>{tagFilter=e.target.value;render();});
$("#exp").addEventListener("click",()=>{
 let rows=DATA.filter(passes);
 const head=["_id",...COLS,"tags","note","reviewed"];
 const q=s=>'"'+(s+"").replace(/"/g,'""')+'"';
 const csv=[head.join(",")].concat(rows.map(r=>head.map(h=>{
  if(h==="tags")return q((review.tags[r._id]||[]).join("|"));
  if(h==="note")return q(review.notes[r._id]||"");
  if(h==="reviewed")return review.reviewed.includes(r._id)?"yes":"";
  return q(r[h]);}).join(","))).join("\n");
 dl(csv,"view-export.csv","text/csv");});
$("#save").addEventListener("click",()=>dl(JSON.stringify(review,null,1),
 "review.json","application/json"));
$("#load").addEventListener("change",e=>{const f=e.target.files[0];if(!f)return;
 const rd=new FileReader();rd.onload=()=>{try{review=JSON.parse(rd.result);
  render();}catch(x){alert("bad review file");}};rd.readAsText(f);});
function dl(text,name,type){const b=new Blob([text],{type});
 const a=document.createElement("a");a.href=URL.createObjectURL(b);
 a.download=name;a.click();}
render();
"""


def build_html(table, review, *, title="analysis_view", rules=None) -> str:
    cols = table.display_columns()
    data = [{k: ("" if r.get(k) is None else str(r.get(k))) for k in
             (["_id"] + cols)} for r in table.rows]
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    rules = rules or []

    ths = "".join(
        f'<th class="h" data-col="{html.escape(c)}">{html.escape(c)}</th>'
        for c in cols)
    fths = "".join(
        f'<th><input data-col="{html.escape(c)}" placeholder="filter"></th>'
        for c in cols)
    rulebox = ""
    if rules:
        rulebox = "<div class='rulebox'>colour rules: " + "; ".join(
            f"{html.escape(r['col'])} ~ /{html.escape(r['match'])}/" for r in
            rules) + "</div>"

    js = (_JS.replace("__DATA__", json.dumps(data))
          .replace("__COLS__", json.dumps(cols))
          .replace("__RULES__", json.dumps(rules))
          .replace("__REVIEW__", json.dumps({
              "tags": review.tags, "notes": review.notes,
              "reviewed": sorted(review.reviewed),
              "tag_colors": review.tag_colors})))

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>
<header><h1>{html.escape(title)} &mdash; {len(data)} rows, {len(cols)} columns
&middot; {len(table.sources)} source(s) &middot; generated {gen}</h1>
<div class="bar">
<input id="q" type="search" placeholder="search all columns…" size="26">
<label><input type="checkbox" id="hr"> hide reviewed</label>
<select id="tagf"></select>
<button id="exp">export view CSV</button>
<button id="save">save review</button>
<label class="rulebox">load review <input type="file" id="load"
 accept=".json"></label>
<span class="count" id="count"></span></div>{rulebox}</header>
<div class="wrap"><table>
<thead><tr><th>&#10003;</th>{ths}<th>tags</th><th>note</th></tr>
<tr class="filters"><th></th>{fths}<th></th><th></th></tr></thead>
<tbody id="body"></tbody></table></div>
<script>{js}</script></body></html>"""
