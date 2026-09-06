import pytest

from analysis_index.indexer import build
from analysis_index.query import QueryError, parse, search
from analysis_index.store import Index

DOCS = {
    "report.txt": "Quarterly report: revenue up, invoice sent to ACME via PayPal.",
    "notes.md": "meeting notes - discuss the wire transfer to the offshore account",
    "chat.log": "alice: send the bitcoin\nbob: wire transfer done\nalice: delete logs",
    "page.html": "<html><body>contact <a href='mailto:mule@evil.com'>us</a> "
                 "about the wire transfer</body></html>",
    "readme.txt": "This is a template for a wire transfer request form.",
}


@pytest.fixture
def idx(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for name, body in DOCS.items():
        (src / name).write_text(body)
    ix = Index(tmp_path / "idx", create=True)
    build(ix, [str(src)], max_size=1 << 20)
    yield ix
    ix.close()


def names(hits):
    return sorted(h.path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for h in hits)


def test_boolean_and_or(idx):
    assert names(search(idx, "wire transfer")) == \
        ["chat.log", "notes.md", "page.html", "readme.txt"]
    assert names(search(idx, "bitcoin OR paypal")) == ["chat.log", "report.txt"]
    assert names(search(idx, "wire AND bitcoin")) == ["chat.log"]


def test_phrase(idx):
    assert names(search(idx, '"wire transfer"')) == \
        ["chat.log", "notes.md", "page.html", "readme.txt"]
    assert names(search(idx, '"transfer wire"')) == []


def test_not(idx):
    assert names(search(idx, "wire transfer -template")) == \
        ["chat.log", "notes.md", "page.html"]
    assert names(search(idx, "transfer NOT bitcoin NOT template")) == \
        ["notes.md", "page.html"]


def test_proximity(idx):
    assert names(search(idx, "send NEAR/2 bitcoin")) == ["chat.log"]
    assert names(search(idx, "send NEAR/1 bitcoin")) == []


def test_regex_and_prefix(idx):
    assert names(search(idx, r"/[a-z]+@evil\.com/")) == ["page.html"]
    assert names(search(idx, "quart*")) == ["report.txt"]


def test_filters(idx):
    assert names(search(idx, "transfer ext:md")) == ["notes.md"]
    assert names(search(idx, "transfer kind:markup")) == ["page.html"]
    assert names(search(idx, "name:chat.log")) == ["chat.log"]


def test_snippets(idx):
    hits = search(idx, "offshore", snippet_chars=60)
    assert hits and "offshore" in hits[0].snippets[0]


def test_incremental_reindex(tmp_path):
    src = tmp_path / "s"
    src.mkdir()
    f = src / "a.txt"
    f.write_text("first version alpha")
    ix = Index(tmp_path / "i", create=True)
    build(ix, [str(src)], max_size=1 << 20)
    assert names(search(ix, "alpha")) == ["a.txt"]

    import os
    import time
    f.write_text("second version beta")
    os.utime(f, (time.time() + 10, time.time() + 10))
    res = build(ix, [str(src)], max_size=1 << 20)
    assert res["updated"] == 1
    assert names(search(ix, "alpha")) == []
    assert names(search(ix, "beta")) == ["a.txt"]
    ix.close()


def test_query_errors():
    for bad in ("", '""', "/[/", "-"):
        with pytest.raises(QueryError):
            parse(bad)
