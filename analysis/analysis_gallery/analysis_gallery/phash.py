"""Perceptual hashing (dHash + aHash) over a grayscale grid, and grouping."""

from __future__ import annotations


def _resize_nn(grid: list[int], w: int, h: int, tw: int, th: int) -> list[int]:
    if w == tw and h == th:
        return grid
    out = [0] * (tw * th)
    for y in range(th):
        sy = min(h - 1, y * h // th)
        for x in range(tw):
            sx = min(w - 1, x * w // tw)
            out[y * tw + x] = grid[sy * w + sx]
    return out


def _resize_area(grid: list[int], w: int, h: int, tw: int, th: int) -> list[int]:
    """Box-average downscale (falls back to nearest on upscale)."""
    if w <= tw or h <= th:
        return _resize_nn(grid, w, h, tw, th)
    out = [0] * (tw * th)
    for ty in range(th):
        y0 = ty * h // th
        y1 = max(y0 + 1, (ty + 1) * h // th)
        for tx in range(tw):
            x0 = tx * w // tw
            x1 = max(x0 + 1, (tx + 1) * w // tw)
            s = c = 0
            for yy in range(y0, y1):
                base = yy * w
                for xx in range(x0, x1):
                    s += grid[base + xx]
                    c += 1
            out[ty * tw + tx] = s // c if c else 0
    return out


def dhash(grid: list[int], w: int, h: int, size: int = 8) -> int:
    small = _resize_area(grid, w, h, size + 1, size)
    bits = 0
    for y in range(size):
        for x in range(size):
            left = small[y * (size + 1) + x]
            right = small[y * (size + 1) + x + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def ahash(grid: list[int], w: int, h: int, size: int = 8) -> int:
    small = _resize_area(grid, w, h, size, size)
    avg = sum(small) / len(small)
    bits = 0
    for v in small:
        bits = (bits << 1) | (1 if v >= avg else 0)
    return bits


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def hex64(v: int) -> str:
    return f"{v:016x}"


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, a: int) -> int:
        while self.p[a] != a:
            self.p[a] = self.p[self.p[a]]
            a = self.p[a]
        return a

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def group(hashes: list[int | None], threshold: int) -> list[int]:
    """Return a group id per item (0 = ungrouped / no hash)."""
    idx = [i for i, hv in enumerate(hashes) if hv is not None]
    uf = _UF(len(hashes))
    # exact-match bucketing first (cheap), then near-match O(n^2) on the rest
    seen: dict[int, int] = {}
    for i in idx:
        hv = hashes[i]
        if hv in seen:
            uf.union(seen[hv], i)
        else:
            seen[hv] = i
    reps = list({uf.find(i) for i in idx})
    for a in range(len(reps)):
        for b in range(a + 1, len(reps)):
            if hamming(hashes[reps[a]], hashes[reps[b]]) <= threshold:
                uf.union(reps[a], reps[b])

    roots: dict[int, list[int]] = {}
    for i in idx:
        roots.setdefault(uf.find(i), []).append(i)
    gid_of = [0] * len(hashes)
    gid = 0
    for root, members in sorted(roots.items(),
                                key=lambda kv: (-len(kv[1]), kv[0])):
        if len(members) < 2:
            continue
        gid += 1
        for m in members:
            gid_of[m] = gid
    return gid_of
