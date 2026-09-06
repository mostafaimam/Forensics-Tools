from windows_reglog.marvin32 import marvin32


def test_deterministic():
    assert marvin32(b"the quick brown fox") == marvin32(b"the quick brown fox")
    assert marvin32(b"a") != marvin32(b"b")


def test_lengths_0_to_4():
    # just exercise every trailing-byte path without raising
    for n in range(0, 9):
        assert isinstance(marvin32(b"x" * n), int)


def test_real_registry_log_vector():
    """First 0x20 bytes of a real HvLE header and its stored hash-2."""
    header32 = bytes.fromhex(
        "48764c45004e00000000000003000000004002000400000056d529cec6324b36")
    assert marvin32(header32) == 0xD71FF4150787EF0C
