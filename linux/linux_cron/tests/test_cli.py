import csv
import json

from _synth import build_root
from linux_cron.cli import main


def _rows(path):
    return list(csv.DictReader(path.open(encoding="utf-8-sig")))


def test_full_scan_csv(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "cron.csv"
    rc = main([str(root), "--csv", str(out), "-q"])
    assert rc == 0
    rows = _rows(out)
    sources = {r["source"] for r in rows}
    assert {"system-crontab", "cron.d", "user-crontab", "anacron",
            "run-parts", "at", "systemd-timer"} <= sources


def test_user_crontab_has_no_user_field(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "c.csv"
    main([str(root), "--csv", str(out), "-q"])
    rows = _rows(out)
    alice = [r for r in rows
             if r["file"].replace("\\", "/").endswith("crontabs/alice")]
    # the "0 9 * * mon-fri /home/alice/report.sh" line: command must be the
    # script, not "mon-fri" swallowed as a user
    line1 = next(r for r in alice if "report.sh" in r["command"])
    assert line1["command"] == "/home/alice/report.sh"
    assert "Monday" in line1["when"]


def test_notable_flags(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "n.csv"
    main([str(root), "--notable-only", "--csv", str(out), "-q"])
    rows = _rows(out)
    joined = "\n".join(r["command"] + " :: " + r["notable"] for r in rows)
    assert "curl" in joined and "pipes" in joined.lower()
    assert any("/dev/tcp" in r["notable"] for r in rows)
    assert any("boot" in r["notable"].lower() for r in rows)
    assert any("base64" in r["notable"].lower() for r in rows)
    assert all(r["notable"] for r in rows)


def test_systemd_timer_resolves_service(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "t.json"
    main([str(root), "--source", "systemd-timer", "--json", str(out), "-q"])
    data = json.loads(out.read_text())
    apt = next(d for d in data if d["file"].endswith("apt-daily.timer"))
    assert "apt.systemd.daily" in apt["command"]
    assert apt["enabled"] == "enabled"
    backdoor = next(d for d in data if d["file"].endswith("backdoor.timer"))
    assert backdoor["enabled"] == "disabled"
    assert "OnCalendar" in apt["schedule"] or "6,18" in apt["schedule"]


def test_at_job_time_and_uid(tmp_path):
    root = build_root(tmp_path)
    out = tmp_path / "a.csv"
    main([str(root), "--source", "at", "--csv", str(out), "-q"])
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["run_as"] == "uid 1000"
    assert rows[0]["schedule"].startswith("run once @ 20")
    assert "exfil.sh" in rows[0]["command"]


def test_explain(capsys):
    assert main(["--explain", "*/5 9-17 * * mon-fri"]) == 0
    out = capsys.readouterr().out
    assert "every 5 minutes" in out and "Monday" in out


def test_single_file(tmp_path, capsys):
    root = build_root(tmp_path)
    f = root / "etc/cron.d/0hourly-evil"
    rc = main(["--file", str(f), "-q"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "flagged" in err


def test_missing_root(tmp_path):
    assert main([str(tmp_path / "nope")]) == 2
