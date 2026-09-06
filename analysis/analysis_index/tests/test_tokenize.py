from analysis_index.tokenize import (
    decode_positions,
    encode_positions,
    index_tokens,
    query_terms,
    tokens,
)


def test_word_tokens_positions():
    got = list(tokens("Hello, WORLD! foo_bar 10.0.0.5"))
    assert [(t, p) for t, p, _ in got] == [
        ("hello", 0), ("world", 1), ("foo", 2), ("bar", 3),
        ("10", 4), ("0", 5), ("0", 6), ("5", 7)]


def test_glued_tokens_share_position():
    terms = {t for t, _, _ in index_tokens("mail me at bob@evil.com now")}
    assert "bob@evil.com" in terms
    assert "bob" in terms and "com" in terms
    # word positions stay contiguous
    words = [p for t, p, _ in index_tokens("a b c") if True]
    assert words == [0, 1, 2]


def test_query_terms():
    assert query_terms("Wire Transfer!") == ["wire", "transfer"]


def test_varint_positions_roundtrip():
    for seq in ([], [0], [5], [0, 1, 2, 300, 300000], list(range(0, 1000, 7))):
        assert decode_positions(encode_positions(seq)) == seq
