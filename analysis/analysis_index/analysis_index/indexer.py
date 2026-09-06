"""Walk paths, extract text, feed the index."""

from __future__ import annotations

from pathlib import Path

from analysis_index.extract import extract
from analysis_index.tokenize import index_tokens


def iter_files(paths, *, recurse=True, follow_symlinks=False):
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            it = p.rglob("*") if recurse else p.glob("*")
            for f in sorted(it):
                try:
                    if f.is_file() and (follow_symlinks or not f.is_symlink()):
                        yield f
                except OSError:
                    continue


def build(index, paths, *, max_size: int, reindex: bool = False,
          recurse: bool = True, follow_symlinks: bool = False, progress=None):
    index.begin_bulk()
    added = updated = skipped = 0
    try:
        for f in iter_files(paths, recurse=recurse,
                            follow_symlinks=follow_symlinks):
            try:
                st = f.stat()
            except OSError:
                continue
            p = str(f.resolve())
            prev = index.has_doc(p)
            if prev is not None and not reindex and abs(prev - st.st_mtime) < 1:
                skipped += 1
                continue
            replacing = prev is not None
            if replacing:
                index.delete_doc(p)
            text, kind = extract(f, max_size=max_size)
            tp: dict[str, list[int]] = {}
            for tok, pos, _off in index_tokens(text):
                tp.setdefault(tok, []).append(pos)
            index.add_doc(p, st.st_size, st.st_mtime,
                          f.suffix.lower().lstrip("."), kind, tp)
            if replacing:
                updated += 1
            else:
                added += 1
            if progress:
                progress(added + updated, p)
    finally:
        index.end_bulk()
    return {"added": added, "updated": updated, "skipped": skipped}
