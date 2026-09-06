import csv
import json

from _synth import build_evtx, event_fragment
from windows_evtx.cli import main


def _evtx(tmp_path, n=6):
    frags = []
    for i in range(n):
        frags.append(event_fragment(
            event_id="4624" if i % 2 else "4688",
            provider="Sec" if i % 2 else "Proc",
            level="0", channel="Security",
            computer="WS01",
            time_created="2024-03-0%d T10:00:00.000000Z".replace(" ", "") % (i + 1),
            data={"k": str(i)},
        ))
    p = tmp_path / "Test.evtx"
    p.write_bytes(build_evtx(frags))
    return p


def test_csv_output(tmp_path):
    p = _evtx(tmp_path)
    out = tmp_path / "o.csv"
    rc = main([str(p), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 6
    assert {r["EventId"] for r in rows} == {"4624", "4688"}
    assert all(r["TimeCreated"].endswith("Z") for r in rows)
    assert rows[0]["PayloadData1"].startswith("k: ")


def test_event_id_filter(tmp_path):
    p = _evtx(tmp_path)
    out = tmp_path / "o.json"
    rc = main([str(p), "--event-id", "4624", "--json", str(out), "-q"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data and all(d["event_id"] == "4624" for d in data)


def test_time_filter(tmp_path):
    p = _evtx(tmp_path)
    out = tmp_path / "o.csv"
    main([str(p), "--from", "2024-03-04", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["TimeCreated"] >= "2024-03-04" for r in rows)


def test_xml_output(tmp_path):
    p = _evtx(tmp_path, 2)
    out = tmp_path / "o.xml"
    main([str(p), "--xml", str(out), "-q"])
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<Events>")
    assert text.count("<Event>") == 2


def test_directory_input(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    _evtx(d, 3)
    (d / "sub").mkdir()
    _evtx(d / "sub", 2)
    out = tmp_path / "all.csv"
    rc = main([str(d), "--csv", str(out), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 5


def test_bad_file(tmp_path, capsys):
    (tmp_path / "x.evtx").write_bytes(b"nope")
    rc = main([str(tmp_path / "x.evtx")])
    assert rc == 2
