from __future__ import annotations

import json

import pytest

from linux_journal import journalfile as jf
from linux_journal.collect import collect
from linux_journal.cli import main

import _synth as S


def _write(tmp_path, **kw):
    d = tmp_path / "var/log/journal/abcd"
    d.mkdir(parents=True)
    return S.write_journal(d / "system.journal", S.sample_entries(), **kw)


def test_header_and_entries(tmp_path):
    p = _write(tmp_path)
    res = jf.read(str(p))
    assert res.header.n_entries == 5
    assert len(res.entries) == 5
    e0 = res.entries[0]
    assert e0.fields["_SYSTEMD_UNIT"] == "ssh.service"
    assert e0.fields["MESSAGE"].startswith("Server listening")
    assert e0.iso.startswith("2026-")


def test_compact_layout(tmp_path):
    d = tmp_path / "var/log/journal/c"
    d.mkdir(parents=True)
    p = S.write_journal(d / "system.journal", S.sample_entries(), compact=True)
    res = jf.read(str(p))
    assert len(res.entries) == 5
    assert res.entries[1].fields["MESSAGE"].startswith("Accepted publickey")


def test_xz_data_object(tmp_path):
    d = tmp_path / "var/log/journal/x"
    d.mkdir(parents=True)
    ents = S.sample_entries()
    p = S.write_journal(d / "system.journal", ents,
                        compress={"MESSAGE": "xz"})
    res = jf.read(str(p))
    msgs = [e.fields.get("MESSAGE", "") for e in res.entries]
    assert any("Accepted publickey" in m for m in msgs)


def test_lz4_data_object_is_flagged(tmp_path):
    d = tmp_path / "var/log/journal/l"
    d.mkdir(parents=True)
    p = S.write_journal(d / "system.journal", S.sample_entries(),
                        compress={"MESSAGE": "lz4"})
    res = collect([str(p)])
    assert res.lz4_skipped >= 1
    assert any("LZ4" in w for w in res.warnings)


def test_discovery_and_merge(tmp_path):
    _write(tmp_path)
    res = collect([str(tmp_path)])
    assert len(res.files) == 1
    assert len(res.entries) == 5
    # sorted by realtime
    ts = [e.realtime_us for e in res.entries]
    assert ts == sorted(ts)
    assert res.boots


def test_flags(tmp_path):
    _write(tmp_path)
    res = collect([str(tmp_path)])
    by_msg = {e.fields["MESSAGE"][:20]: e for e in res.entries}
    assert any("SSH login accepted" in n
               for n in by_msg["Accepted publickey f"].notable)
    assert any("SSH authentication failure" in n
               for n in by_msg["Failed password for "].notable)
    assert any("segfault" in n for n in by_msg["collector[2200]: seg"].notable)
    cradle = by_msg["running update"]
    j = " ".join(cradle.notable)
    assert "user-writable path" in j and "cradle" in j


def test_cli_csv_json_filters(tmp_path):
    _write(tmp_path)
    csv_p = tmp_path / "j.csv"
    js_p = tmp_path / "j.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and len(data) == 5
    assert "fields" in data[0]

    main([str(tmp_path), "--priority", "err", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(int(r["fields"].get("PRIORITY", "6")) <= 3 for r in got)

    main([str(tmp_path), "--field", "_COMM=sshd", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["fields"]["_COMM"] == "sshd" for r in got)


def test_cli_list_boots(tmp_path, capsys):
    _write(tmp_path)
    rc = main([str(tmp_path), "--list-boots"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "2026-" in out


def test_cli_grep_and_notable(tmp_path):
    _write(tmp_path)
    js_p = tmp_path / "j.json"
    main([str(tmp_path), "--notable-only", "--min-severity", "high",
          "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_bad_signature(tmp_path):
    p = tmp_path / "x.journal"
    p.write_bytes(b"NOTAJOURNAL" + b"\x00" * 400)
    with pytest.raises(jf.JournalError):
        jf.read(str(p))


def test_csv_injection_guard():
    from linux_journal.tracelib import sanitize
    assert sanitize("=HYPERLINK(1)") == "'=HYPERLINK(1)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
