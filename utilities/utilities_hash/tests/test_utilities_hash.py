from __future__ import annotations

import hashlib
import json

import pytest

from utilities_hash.hashing import hash_all
from utilities_hash.verify import diff, load_manifest
from utilities_hash.cli import main


def _tree(root):
    (root / "a").mkdir()
    (root / "a" / "one.txt").write_bytes(b"hello world")
    (root / "a" / "two.bin").write_bytes(b"\x00\x01\x02" * 100)
    (root / "b").mkdir()
    (root / "b" / "three.log").write_text("log line\n")
    (root / "skip.tmp").write_bytes(b"junk")
    return root


def test_hash_all(tmp_path):
    _tree(tmp_path)
    res = hash_all([str(tmp_path)], ["md5", "sha256"])
    assert len(res.files) == 4
    one = next(f for f in res.files if f.rel == "a/one.txt")
    assert one.digests["sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert one.digests["md5"] == hashlib.md5(b"hello world").hexdigest()
    assert one.size == 11


def test_exclude_and_norecurse(tmp_path):
    _tree(tmp_path)
    res = hash_all([str(tmp_path)], ["sha1"], exclude=["*.tmp"])
    assert not any(f.rel.endswith(".tmp") for f in res.files)
    res2 = hash_all([str(tmp_path)], ["sha1"], recurse=False)
    assert {f.rel for f in res2.files} == {"skip.tmp"}


def test_cli_manifest_and_sum(tmp_path):
    _tree(tmp_path)
    csv_p = tmp_path / "m.csv"
    js_p = tmp_path / "m.json"
    sum_p = tmp_path / "h.txt"
    rc = main([str(tmp_path), "--algo", "sha256,md5", "--csv", str(csv_p),
               "--json", str(js_p), "--sum-out", str(sum_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 4
    lines = sum_p.read_text().strip().splitlines()
    assert all(len(ln.split("  ")[0]) == 64 for ln in lines)


def test_verify_roundtrip(tmp_path):
    _tree(tmp_path)
    man = tmp_path / "m.csv"
    main([str(tmp_path), "--csv", str(man), "-q"])

    # mutate: change one, add one, remove one, move one
    (tmp_path / "a" / "one.txt").write_bytes(b"HELLO WORLD changed")
    (tmp_path / "b" / "new.txt").write_bytes(b"brand new")
    (tmp_path / "a" / "two.bin").unlink()
    (tmp_path / "b" / "moved.log").write_text("log line\n")   # == b/three.log
    (tmp_path / "b" / "three.log").unlink()

    d = diff(load_manifest(str(man)), hash_all([str(tmp_path)], ["sha256"]))
    assert [c[0] for c in d.changed] == ["a/one.txt"]
    assert "b/new.txt" in d.added
    assert "a/two.bin" in d.removed
    assert d.moved and d.moved[0][0] == "b/three.log" \
        and d.moved[0][1] == "b/moved.log"

    rc = main([str(tmp_path), "--verify", str(man), "-q"])
    assert rc == 1   # differences -> nonzero


def test_verify_sum_format(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "x.txt").write_bytes(b"data")
    h = hashlib.sha256(b"data").hexdigest()
    (tmp_path / "man.sha256").write_text(f"{h}  x.txt\n")
    rc = main([str(d), "--verify", str(tmp_path / "man.sha256"), "-q"])
    assert rc == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
