from _synth import build_evtx, event_fragment, event_fragment_templated
from windows_evtx.evtx import parse_evtx


def test_plain_event():
    frag = event_fragment(
        event_id="4624", provider="Microsoft-Windows-Security-Auditing",
        level="0", channel="Security", computer="WS01",
        time_created="2024-03-05T10:00:00.000000Z",
        data={"TargetUserName": "alice", "LogonType": "3"},
    )
    recs = list(parse_evtx(build_evtx([frag])))
    assert len(recs) == 1
    r = recs[0]
    assert not r.parse_error
    assert r.event_id == "4624"
    assert r.provider == "Microsoft-Windows-Security-Auditing"
    assert r.channel == "Security"
    assert r.computer == "WS01"
    assert r.user_id == "S-1-5-18"
    assert r.process_id == "1234" and r.thread_id == "5678"
    assert r.time_created_utc == "2024-03-05T10:00:00.000000Z"
    assert r.data["TargetUserName"] == "alice"
    assert r.data["LogonType"] == "3"
    assert "<EventID>4624</EventID>" in r.xml


def test_multiple_records():
    frags = [
        event_fragment(event_id=str(4000 + i), provider="P", level="4",
                       channel="System", computer="WS01",
                       time_created="2024-03-05T10:00:0%d.000000Z" % i,
                       data={"n": str(i)})
        for i in range(5)
    ]
    recs = list(parse_evtx(build_evtx(frags)))
    assert [r.event_id for r in recs] == ["4000", "4001", "4002", "4003", "4004"]
    assert all(not r.parse_error for r in recs)


def test_templated_event_with_substitutions():
    frag = event_fragment_templated(values=[
        (0x01, "7045"), (0x01, "SRV-DC-01"), (0x01, "A new service was installed"),
    ])
    recs = list(parse_evtx(build_evtx([frag])))
    assert len(recs) == 1
    r = recs[0]
    assert not r.parse_error, r.parse_error
    assert r.event_id == "7045"
    assert r.computer == "SRV-DC-01"
    assert r.data["Payload"] == "A new service was installed"


def test_two_templated_records():
    a = lambda off: event_fragment_templated(
        values=[(0x01, "1"), (0x01, "H1"), (0x01, "x")],
        binxml_offset=off, template_id=0xA)
    b = lambda off: event_fragment_templated(
        values=[(0x01, "2"), (0x01, "H2"), (0x01, "y")],
        binxml_offset=off, template_id=0xB)
    recs = list(parse_evtx(build_evtx([a, b])))
    assert [r.event_id for r in recs] == ["1", "2"]
    assert [r.computer for r in recs] == ["H1", "H2"]
    assert [r.data["Payload"] for r in recs] == ["x", "y"]


def test_not_evtx():
    import pytest

    from windows_evtx.evtx import EvtxError

    with pytest.raises(EvtxError):
        list(parse_evtx(b"PK\x03\x04 not evtx"))
