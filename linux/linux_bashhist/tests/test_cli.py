import csv
import json

from _synth import build_root
from linux_bashhist.cli import main


def _rows(p):
    return list(csv.DictReader(p.open(encoding="utf-8-sig")))


def test_full_scan(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "h.csv"
    rc = main([str(root), "--csv", str(out), "-q"])
    assert rc == 0
    rows = _rows(out)
    users = {r["user"] for r in rows}
    assert {"root", "alice", "bob"} <= users
    shells = {r["shell"] for r in rows}
    assert {"bash", "zsh", "fish", "python"} <= shells
    # timestamped bash entries sort before the plain ones (None -> epoch min)
    ts = [r["timestamp_utc"] for r in rows if r["timestamp_utc"]]
    assert ts == sorted(ts)


def test_notable_only(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "n.csv"
    main([str(root), "--notable-only", "--csv", str(out), "-q"])
    rows = _rows(out)
    joined = "\n".join(r["notable"] for r in rows)
    assert "interpreter" in joined            # curl | bash
    assert "/dev/tcp" in joined               # fish reverse shell
    assert "wipes shell history" in joined    # history -c
    assert "encoded payload" in joined or "base64" in joined
    assert all(r["notable"] for r in rows)


def test_user_and_grep_filter(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "u.csv"
    main([str(root), "--user", "alice", "--grep", "wget|curl",
          "--csv", str(out), "-q"])
    rows = _rows(out)
    assert rows and all(r["user"] == "alice" for r in rows)
    assert all("wget" in r["command"] or "curl" in r["command"] for r in rows)


def test_tampering_markers(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "m.json"
    main([str(root), "--with-notes", "--json", str(out), "-q"])
    data = json.loads(out.read_text())
    notes = " ".join(d["note"] for d in data)
    assert "empty" in notes                       # carol's wiped history
    assert "out-of-order" in notes                # root's reordered timestamps


def test_single_file_with_user(tmp_path):
    root = build_root(tmp_path)
    f = root / "home/alice/.zsh_history"
    out = tmp_path / "s.csv"
    rc = main(["--file", str(f), "--user", "alice", "--csv", str(out), "-q"])
    assert rc == 0
    rows = _rows(out)
    assert rows and all(r["user"] == "alice" and r["shell"] == "zsh"
                        for r in rows)


def test_time_window(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "w.csv"
    main([str(root), "--from", "2024-02-10T08:00:30", "--to",
          "2024-02-10T08:02:00", "--csv", str(out), "-q"])
    rows = _rows(out)
    assert rows and all(r["timestamp_utc"] for r in rows)
    assert all("2024-02-10T08:0" in r["timestamp_utc"] for r in rows)


def test_missing():
    assert main([str("/no/such/root")]) == 2
