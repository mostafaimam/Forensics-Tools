"""Parse the Chromium SNSS session / tab command stream."""

from __future__ import annotations

import struct
from pathlib import Path

from browser_sessions import timeconv as _t
from browser_sessions.model import Tab

_SIGNATURE = 0x53534E53                       # "SNSS"

# command ids (components/sessions/core/session_service_commands.cc)
CMD_SET_TAB_WINDOW = 0
CMD_SET_TAB_INDEX = 2
CMD_UPDATE_TAB_NAVIGATION = 6
CMD_SET_SELECTED_NAV_INDEX = 7
CMD_SET_PINNED_STATE = 12
CMD_TAB_CLOSED = 16
CMD_WINDOW_CLOSED = 17
CMD_SET_ACTIVE_WINDOW = 20
CMD_LAST_ACTIVE_TIME = 21
# tab-restore service stream
CMD_TRS_NAVIGATION = 1
CMD_TRS_SELECTED_NAV = 3


class _Pickle:
    """A tolerant reader for the Chrome ``base::Pickle`` wire format."""

    def __init__(self, data: bytes):
        # data starts with a uint32 payload size
        if len(data) < 4:
            self.buf = b""
            self.pos = 0
            return
        size = struct.unpack_from("<I", data, 0)[0]
        self.buf = data[4:4 + size] if 4 + size <= len(data) else data[4:]
        self.pos = 0

    def _align(self):
        self.pos = (self.pos + 3) & ~3

    def read_int(self):
        if self.pos + 4 > len(self.buf):
            raise EOFError
        v = struct.unpack_from("<i", self.buf, self.pos)[0]
        self.pos += 4
        return v

    def read_uint(self):
        if self.pos + 4 > len(self.buf):
            raise EOFError
        v = struct.unpack_from("<I", self.buf, self.pos)[0]
        self.pos += 4
        return v

    def read_int64(self):
        if self.pos + 8 > len(self.buf):
            raise EOFError
        v = struct.unpack_from("<q", self.buf, self.pos)[0]
        self.pos += 8
        self._align()
        return v

    def read_string(self):
        n = self.read_uint()
        if n > len(self.buf) - self.pos:
            raise EOFError
        s = self.buf[self.pos:self.pos + n].decode("utf-8", "replace")
        self.pos += n
        self._align()
        return s

    def read_string16(self):
        n = self.read_uint()
        b = n * 2
        if b > len(self.buf) - self.pos:
            raise EOFError
        s = self.buf[self.pos:self.pos + b].decode("utf-16-le", "replace")
        self.pos += b
        self._align()
        return s


def _iter_commands(data: bytes):
    if len(data) < 8:
        return
    sig, ver = struct.unpack_from("<ii", data, 0)
    if sig != _SIGNATURE:
        return
    pos = 8
    n = len(data)
    while pos + 2 <= n:
        (size,) = struct.unpack_from("<H", data, pos)
        pos += 2
        if size == 0 or pos + size > n:
            break
        cmd_id = data[pos]
        content = data[pos + 1:pos + size]
        pos += size
        yield cmd_id, content


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
    return "Chrome"


def parse(path: str) -> list[Tab]:
    p = str(path)
    data = Path(p).read_bytes()
    if not data[:4] == struct.pack("<i", _SIGNATURE):
        return []
    br, pr = _browser(p), _profile(p)
    is_restore = "tabs" in Path(p).name.lower()
    fname = Path(p).name
    tabs: dict[int, Tab] = {}
    navs: dict[tuple, tuple] = {}                 # (tab_id, idx) -> (url,title)
    max_idx: dict[int, int] = {}

    def tab(tid: int) -> Tab:
        if tid not in tabs:
            tabs[tid] = Tab(browser=br, profile=pr, source_file=fname)
        return tabs[tid]

    for cmd_id, content in _iter_commands(data):
        try:
            if cmd_id == CMD_SET_TAB_WINDOW and len(content) >= 8:
                win, tid = struct.unpack_from("<ii", content, 0)
                tab(tid).window = f"window {win}"
            elif cmd_id == CMD_SET_TAB_INDEX:
                pk = _Pickle(content)
                tid = pk.read_int()
                tab(tid).index = pk.read_int()
            elif cmd_id == CMD_UPDATE_TAB_NAVIGATION:
                pk = _Pickle(content)
                tid = pk.read_int()
                idx = pk.read_int()
                url = pk.read_string()
                title = pk.read_string16()
                if url:
                    navs[(tid, idx)] = (url, title)
                    max_idx[tid] = max(max_idx.get(tid, -1), idx)
            elif cmd_id == CMD_SET_PINNED_STATE:
                pk = _Pickle(content)
                tid = pk.read_int()
                tab(tid).pinned = bool(pk.read_int())
            elif cmd_id == CMD_TAB_CLOSED and len(content) >= 4:
                tid = struct.unpack_from("<i", content, 0)[0]
                tab(tid).closed = True
            elif cmd_id == CMD_LAST_ACTIVE_TIME:
                pk = _Pickle(content)
                tid = pk.read_int()
                tab(tid).last_accessed = _t.chrome(pk.read_int64())
        except (EOFError, struct.error, IndexError):
            continue

    by_tab: dict[int, list] = {}
    for (tid, idx), (url, title) in sorted(navs.items()):
        by_tab.setdefault(tid, []).append((url, title))
        if idx == max_idx.get(tid):
            tab(tid).current_url, tab(tid).current_title = url, title

    out = []
    for tid, t in tabs.items():
        hist = by_tab.get(tid, [])
        t.history = hist
        t.entry_count = len(hist)
        if not t.current_url and hist:
            t.current_url, t.current_title = hist[-1]
        if not (t.current_url or hist):
            continue
        if is_restore and not t.closed:
            t.closed = True
        out.append(t)
    return out
