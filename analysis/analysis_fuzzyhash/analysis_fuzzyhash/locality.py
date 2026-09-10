"""A TLSH-style whole-file locality digest (byte-trigram histogram)."""

from __future__ import annotations

# Pearson permutation table (standard)
_T = (
    98, 6, 85, 150, 36, 23, 112, 164, 135, 207, 169, 5, 26, 64, 165, 219,
    61, 20, 68, 89, 130, 63, 52, 102, 24, 229, 132, 245, 80, 216, 195, 115,
    90, 168, 156, 203, 177, 120, 2, 190, 188, 7, 100, 185, 174, 243, 162, 10,
    237, 18, 253, 225, 8, 208, 172, 244, 255, 126, 101, 79, 145, 235, 228, 121,
    123, 251, 67, 250, 161, 0, 107, 97, 241, 111, 181, 82, 249, 33, 69, 55,
    59, 153, 29, 9, 213, 167, 84, 93, 30, 46, 94, 75, 151, 114, 73, 222,
    197, 96, 210, 45, 16, 227, 248, 202, 51, 152, 252, 125, 81, 206, 215, 186,
    39, 158, 178, 187, 131, 136, 1, 49, 50, 17, 141, 91, 47, 129, 60, 99,
    154, 35, 86, 171, 105, 34, 38, 200, 147, 58, 77, 118, 173, 246, 76, 254,
    133, 232, 196, 144, 198, 124, 53, 4, 108, 74, 223, 234, 134, 230, 157, 139,
    189, 205, 199, 128, 176, 19, 211, 236, 127, 192, 231, 70, 233, 88, 146, 44,
    183, 201, 22, 83, 13, 214, 116, 109, 159, 32, 95, 226, 140, 220, 57, 12,
    221, 31, 209, 182, 143, 92, 149, 184, 148, 62, 113, 65, 37, 27, 106, 166,
    3, 14, 204, 72, 21, 41, 56, 66, 28, 193, 40, 217, 25, 54, 179, 117,
    238, 87, 240, 155, 180, 170, 242, 212, 191, 163, 78, 218, 137, 194, 175, 110,
    43, 119, 224, 71, 122, 142, 42, 160, 104, 48, 247, 103, 15, 11, 138, 239,
)

_WINDOW = 5
_BUCKETS = 128


def _pearson(a, b, c):
    h = _T[c]
    h = _T[h ^ a]
    h = _T[h ^ b]
    return h


def digest(data: bytes) -> str:
    if len(data) < 32:
        return "T0"
    counts = [0] * _BUCKETS
    win = data[:_WINDOW]
    n = len(data)
    for i in range(_WINDOW, n):
        b = data[i]
        b1, b2, b3, b4 = win[-1], win[-2], win[-3], win[-4]
        for (x, y) in ((b1, b2), (b1, b3), (b1, b4), (b2, b3), (b2, b4)):
            counts[_pearson(b, x, y) % _BUCKETS] += 1
        win = win[1:] + bytes([b])

    mean = (sum(counts) / _BUCKETS) or 1.0
    # bucket each count against fixed multiples of the mean - captures the
    # *shape*, and stays informative for a near-flat histogram
    bits = []
    for c in counts:
        r = c / mean
        if r <= 0.5:
            bits.append(0)
        elif r <= 0.9:
            bits.append(1)
        elif r <= 1.3:
            bits.append(2)
        else:
            bits.append(3)
    body = 0
    for v in bits:
        body = (body << 2) | v
    length_code = min(len(data).bit_length(), 255)
    return f"T1{length_code:02x}{body:0{_BUCKETS // 2}x}"


def distance(d1: str, d2: str) -> int:
    """Lower = more similar. 0 identical; ~300 unrelated."""
    if not (d1.startswith("T1") and d2.startswith("T1")):
        return 1000
    b1 = int(d1[4:], 16)
    b2 = int(d2[4:], 16)
    diff = 0
    for _ in range(_BUCKETS):
        diff += abs((b1 & 3) - (b2 & 3))
        b1 >>= 2
        b2 >>= 2
    lc1 = int(d1[2:4], 16)
    lc2 = int(d2[2:4], 16)
    return diff + abs(lc1 - lc2)


def similarity(d1: str, d2: str) -> int:
    """0-100 (100 identical)."""
    dist = distance(d1, d2)
    return max(0, 100 - dist * 100 // 384)
