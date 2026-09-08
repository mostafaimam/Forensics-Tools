"""Parse Chromium ``Bookmarks`` JSON and Firefox ``moz_bookmarks``."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from browser_bookmarks import timeconv as _t
from browser_bookmarks.dbopen import connect, has_table, query


@dataclass
class Bookmark:
    browser: str = ""
    profile: str = ""
    folder: str = ""                 # "Bookmarks Bar/Work/Tools"
    title: str = ""
    url: str = ""
    date_added: str = ""
    date_modified: str = ""
    date_last_used: str = ""
    guid: str = ""
    source: str = ""                 # bookmarks | bak-only | places
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "date_added": self.date_added, "date_modified": self.date_modified,
            "date_last_used": self.date_last_used,
            "browser": self.browser, "profile": self.profile,
            "folder": self.folder, "title": self.title, "url": self.url,
            "guid": self.guid, "source": self.source,
            "notable": ";".join(self.notable),
        }


def _profile(p: str) -> str:
    for seg in reversed(Path(p).parts[:-1]):
        low = seg.lower()
        if low.startswith(("profile", "default")) or ".default" in low:
            return seg
    return ""


def _browser(p: str) -> str:
    s = p.lower().replace("\\", "/")
    for needle, name in (("edge", "Edge"), ("brave", "Brave"),
                         ("opera", "Opera"), ("vivaldi", "Vivaldi"),
                         ("chromium", "Chromium")):
        if needle in s:
            return name
    return "Firefox" if "places.sqlite" in s else "Chrome"


def _flag(bm: Bookmark) -> None:
    u = bm.url
    low = u.lower()
    if low.startswith("javascript:"):
        bm.notable.append("bookmarklet (javascript: URL)")
    elif low.startswith("file:"):
        bm.notable.append("bookmark to a local file (file://)")
    elif low.startswith(("ftp:", "ftps:", "sftp:")):
        bm.notable.append("bookmark to an FTP resource")
    elif low.startswith(("chrome:", "edge:", "about:", "chrome-extension:")):
        bm.notable.append("bookmark to a browser-internal page")
    try:
        pr = urlparse(u)
        host = pr.hostname or ""
        if host:
            try:
                if ipaddress.ip_address(host).is_global:
                    bm.notable.append("bookmark to a raw IP address")
            except ValueError:
                pass
        if pr.port and pr.port not in (80, 443, 8080, 8443):
            bm.notable.append(f"bookmark to a non-standard port ({pr.port})")
    except ValueError:
        pass
    if bm.source == "bak-only":
        bm.notable.append("only present in Bookmarks.bak (deleted bookmark)")


# --------------------------------------------------------------------------
# Chromium
# --------------------------------------------------------------------------

_ROOT_NAMES = {"bookmark_bar": "Bookmarks Bar", "other": "Other Bookmarks",
               "synced": "Mobile Bookmarks"}


def _walk_chromium(node: dict, path: str, browser: str, profile: str,
                   source: str, into: dict) -> None:
    if node.get("type") == "folder":
        name = node.get("name", "")
        sub = f"{path}/{name}" if path else name
        for ch in node.get("children", []):
            _walk_chromium(ch, sub, browser, profile, source, into)
    elif node.get("type") == "url":
        guid = node.get("guid") or node.get("id") or node.get("url")
        bm = Bookmark(
            browser=browser, profile=profile, folder=path,
            title=node.get("name", ""), url=node.get("url", ""),
            date_added=_t.chrome(node.get("date_added")),
            date_modified=_t.chrome(node.get("date_modified")),
            date_last_used=_t.chrome(node.get("date_last_used")),
            guid=str(guid), source=source)
        into[(bm.url, bm.folder, bm.title)] = bm


def parse_chromium(json_path: str) -> list[Bookmark]:
    p = str(json_path)
    br, pr = _browser(p), _profile(p)
    cur: dict = {}
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    for key, root in (data.get("roots") or {}).items():
        if not isinstance(root, dict):
            continue
        root.setdefault("type", "folder")
        root.setdefault("name", _ROOT_NAMES.get(key, key))
        _walk_chromium(root, "", br, pr, "bookmarks", cur)

    bak = Path(p).with_name(Path(p).name + ".bak")
    if bak.exists():
        prev: dict = {}
        try:
            bdata = json.loads(bak.read_text(encoding="utf-8",
                                             errors="replace"))
            for key, root in (bdata.get("roots") or {}).items():
                if isinstance(root, dict):
                    root.setdefault("type", "folder")
                    root.setdefault("name", _ROOT_NAMES.get(key, key))
                    _walk_chromium(root, "", br, pr, "bak-only", prev)
        except (OSError, ValueError):
            prev = {}
        for k, bm in prev.items():
            if k not in cur:
                cur[k] = bm

    out = list(cur.values())
    for bm in out:
        _flag(bm)
    return out


# --------------------------------------------------------------------------
# Firefox
# --------------------------------------------------------------------------

def parse_firefox(db_path: str) -> list[Bookmark]:
    out: list[Bookmark] = []
    p = str(db_path)
    pr = _profile(p)
    with connect(p) as con:
        if not has_table(con, "moz_bookmarks"):
            return out
        places = {r["id"]: r["url"] for r in query(
            con, "SELECT id, url FROM moz_places")}
        nodes = {r["id"]: dict(r) for r in query(
            con, "SELECT id, type, parent, title, fk, dateAdded, "
                 "lastModified, guid FROM moz_bookmarks")}

        def folder_path(nid: int) -> str:
            parts = []
            seen = set()
            cur = nodes.get(nid)
            while cur and cur["id"] not in seen:
                seen.add(cur["id"])
                if cur["parent"] and cur["parent"] in nodes:
                    par = nodes[cur["parent"]]
                    if par.get("title"):
                        parts.append(par["title"])
                    cur = par
                else:
                    break
            return "/".join(reversed(parts))

        for n in nodes.values():
            if n["type"] != 1:                    # 1 = bookmark
                continue
            url = places.get(n["fk"], "")
            bm = Bookmark(
                browser="Firefox", profile=pr,
                folder=folder_path(n["id"]) or "(root)",
                title=n.get("title") or "", url=url,
                date_added=_t.webkit_us(n.get("dateAdded")),
                date_modified=_t.webkit_us(n.get("lastModified")),
                guid=n.get("guid") or str(n["id"]), source="places")
            _flag(bm)
            out.append(bm)
    return out
