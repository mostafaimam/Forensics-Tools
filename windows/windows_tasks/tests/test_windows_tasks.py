from __future__ import annotations

import json

import pytest

from windows_tasks import taskcache as TC
from windows_tasks import taskxml as TX
from windows_tasks.analyze import analyze
from windows_tasks.cli import main

import _synth as S
import _hive_synth as H


def _by_path(res):
    return {t.task_path: t for t in res.tasks}


def test_xml_parse(tmp_path):
    S.build_root(tmp_path, with_hive=False)
    res = analyze([str(tmp_path)])
    t = _by_path(res)["\\Microsoft\\Windows\\Defender\\GoodScan"]
    assert t.author == "Microsoft Corporation"
    assert t.run_as == "S-1-5-18"
    assert "MpCmdRun.exe -Scan" in t.command_line
    assert t.reg_date == "2026-02-01T03:14:00"
    assert any("logon" in tr for tr in t.triggers)


def test_hive_taskcache():
    cache = TC.from_hive_bytes(H.build_software_hive())
    assert len(cache.entries) == 4
    evil = cache.entries[H.G_EVIL]
    assert evil.path == "\\EvilPersist"
    assert evil.tree_present is True
    assert evil.registered == "2026-02-01T03:14:00Z"
    assert evil.last_run == "2026-02-10T06:00:00Z"
    hidden = cache.entries[H.G_HIDDEN]
    assert hidden.tree_present is False


def test_join_and_flags(tmp_path):
    S.build_root(tmp_path)
    res = _by_path(analyze([str(tmp_path)]))

    evil = res["\\EvilPersist"]
    assert evil.guid == H.G_EVIL
    assert evil.registered == "2026-02-01T03:14:00Z"
    assert evil.last_run == "2026-02-10T06:00:00Z"
    j = " ".join(evil.notable)
    assert "user-writable path" in j
    assert "SYSTEM from a user-writable path" in j
    assert "registered outside" in j
    assert "no author recorded" in j

    hb = res["\\HiddenBackdoor"]
    j = " ".join(hb.notable)
    assert "living-off-the-land binary" in j
    assert "encoded / obfuscated command line" in j
    assert "task is hidden" in j
    assert "absent from the Tree" in j     # in Tasks, not in Tree

    upd = res["\\Microsoft\\Windows\\UpdateOrchestrator\\SysUpdate"]
    assert any("living-off-the-land binary in the action (mshta)" in n
               for n in upd.notable)

    ghost = res["\\RegistryGhost"]
    assert ghost.registry_only is True
    assert any("registry-only task" in n for n in ghost.notable)

    good = res["\\Microsoft\\Windows\\Defender\\GoodScan"]
    from windows_tasks.flags import severity
    assert severity(good.notable) in ("none", "low")


def test_xml_only_without_registry_entry(tmp_path):
    S.build_root(tmp_path)
    res = _by_path(analyze([str(tmp_path)]))
    xo = res["\\XmlOnlyJob"]
    assert xo.xml_only is True
    assert any("XML-only task" in n for n in xo.notable)


def test_com_handler(tmp_path):
    (tmp_path / "Windows/System32/Tasks").mkdir(parents=True)
    S._write(tmp_path / "Windows/System32/Tasks", "\\ComTask",
             S._task_xml("\\ComTask", "x", command="",
                         com_class="{9ACF6F92-5F1C-4F1A-8C2B-000000000000}"))
    res = _by_path(analyze([str(tmp_path)]))
    t = res["\\ComTask"]
    assert "comhandler" in t.action_kinds
    assert any("ComHandler action" in n for n in t.notable)


def test_utf16_and_bom_handling(tmp_path):
    base = tmp_path / "Windows/System32/Tasks"
    base.mkdir(parents=True)
    xml = S._task_xml("\\Plain", "me", command="C:\\Windows\\notepad.exe")
    (base / "Plain").write_bytes(b"\xff\xfe" + xml.encode("utf-16-le"))
    td = TX.parse(base / "Plain")
    assert td.uri == "\\Plain"
    assert td.actions[0].command == "C:\\Windows\\notepad.exe"


def test_cli_csv_json_filters(tmp_path):
    S.build_root(tmp_path)
    csv_p = tmp_path / "t.csv"
    js_p = tmp_path / "t.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and len(data) >= 5

    main([str(tmp_path), "--hidden-only", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["hidden"] == "yes" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_no_hive_partial_note(tmp_path):
    S.build_root(tmp_path, with_hive=False)
    csv_p = tmp_path / "t.csv"
    main([str(tmp_path), "--csv", str(csv_p), "-q"])
    m = json.loads((tmp_path / "t.csv.manifest.json").read_text())
    assert any("SOFTWARE hive" in w.get("message", "")
               for w in m.get("warnings", []))


def test_csv_injection_guard():
    from windows_tasks.tracelib import sanitize
    assert sanitize("=cmd|calc") == "'=cmd|calc"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
