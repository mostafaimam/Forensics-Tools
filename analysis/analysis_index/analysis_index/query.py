"""Parse and execute a search query against an :class:`Index`."""

from __future__ import annotations

import math
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from analysis_index.extract import extract
from analysis_index.tokenize import query_terms, tokens

_NEAR_RE = re.compile(r"^near/(\d+)$", re.I)


class QueryError(ValueError):
    pass


@dataclass
class Hit:
    path: str
    score: float
    matches: int
    kind: str
    size: int
    snippets: list = field(default_factory=list)


# -- parsing -------------------------------------------------------
def _split_tokens(q: str) -> list[str]:
    lex = shlex.shlex(q, posix=False)
    lex.whitespace_split = True
    lex.commenters = ""
    lex.quotes = '"'
    out = []
    for t in lex:
        out.append(t)
    return out


@dataclass
class Atom:
    kind: str            # term | prefix | phrase | regex | near
    value: object
    negate: bool = False
    near_n: int = 0
    near_b: object = None


@dataclass
class ParsedQuery:
    or_groups: list          # list[list[Atom]] - OR of AND-groups
    filters: dict = field(default_factory=dict)
    match_all: bool = False   # filter-only query


def parse(q: str) -> ParsedQuery:
    raw = _split_tokens(q)
    if not raw:
        raise QueryError("empty query")
    filters: dict = {}
    or_groups: list[list[Atom]] = [[]]
    i = 0
    negate_next = False
    while i < len(raw):
        tok = raw[i]
        low = tok.lower()
        if low == "or":
            or_groups.append([])
            i += 1
            continue
        if low == "and":
            i += 1
            continue
        if low in ("not", "-") and i + 1 < len(raw):
            negate_next = True
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            negate_next = True
            tok = tok[1:]
            low = tok.lower()
        if ":" in tok and not tok.startswith(('"', "/")):
            key, _, val = tok.partition(":")
            if key.lower() in ("ext", "path", "kind", "name"):
                filters.setdefault(key.lower(), []).append(val.lower())
                i += 1
                negate_next = False
                continue
        atom = _atom(tok)
        # look-ahead for NEAR/n
        if i + 2 < len(raw) and _NEAR_RE.match(raw[i + 1].lower()):
            n = int(_NEAR_RE.match(raw[i + 1].lower()).group(1))
            b = _atom(raw[i + 2])
            atom = Atom("near", atom, near_n=n, near_b=b)
            i += 2
        atom.negate = negate_next
        negate_next = False
        or_groups[-1].append(atom)
        i += 1
    or_groups = [g for g in or_groups if g]
    if not or_groups:
        if filters:
            return ParsedQuery([], filters, match_all=True)
        raise QueryError("query has no searchable terms")
    return ParsedQuery(or_groups, filters)


def _atom(tok: str) -> Atom:
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        terms = query_terms(tok[1:-1])
        if not terms:
            raise QueryError(f"empty phrase: {tok}")
        return Atom("phrase", terms)
    if len(tok) >= 2 and tok[0] == "/" and tok[-1] == "/":
        try:
            re.compile(tok[1:-1])
        except re.error as e:
            raise QueryError(f"bad regex {tok}: {e}") from None
        return Atom("regex", tok[1:-1])
    if tok.endswith("*") and len(tok) > 1:
        return Atom("prefix", tok[:-1].lower())
    t = query_terms(tok)
    if not t:
        raise QueryError(f"not a searchable term: {tok!r}")
    return Atom("phrase", t) if len(t) > 1 else Atom("term", t[0])


# -- execution ----------------------------------------------------
def _atom_docs(index, atom: Atom):
    """Return {doc_id: [match positions]} for a positive atom."""
    if atom.kind == "term":
        return index.postings(atom.value)
    if atom.kind == "prefix":
        merged: dict[int, list[int]] = {}
        for term in index.terms_like(atom.value + "*"):
            for d, ps in index.postings(term).items():
                merged.setdefault(d, []).extend(ps)
        return merged
    if atom.kind == "regex":
        merged = {}
        for term in index.terms_matching(atom.value):
            for d, ps in index.postings(term).items():
                merged.setdefault(d, []).extend(ps)
        return merged
    if atom.kind == "phrase":
        return _phrase_docs(index, atom.value)
    if atom.kind == "near":
        a = _atom_docs(index, atom.value)
        b = _atom_docs(index, atom.near_b)
        out = {}
        for d in set(a) & set(b):
            pa = sorted(a[d])
            pb = sorted(b[d])
            hits = [x for x in pa
                    if any(abs(x - y) <= atom.near_n for y in pb)]
            if hits:
                out[d] = hits
        return out
    return {}


def _phrase_docs(index, terms: list[str]):
    per = [index.postings(t) for t in terms]
    if not per or any(not p for p in per):
        return {}
    common = set(per[0])
    for p in per[1:]:
        common &= set(p)
    out = {}
    for d in common:
        base = set(per[0][d])
        starts = [s for s in base
                  if all((s + k) in set(per[k][d]) for k in range(1, len(terms)))]
        if starts:
            out[d] = starts
    return out


def _pass_filters(meta: dict, filters: dict) -> bool:
    for key, vals in filters.items():
        if key == "ext":
            if (meta.get("ext") or "").lower() not in vals:
                return False
        elif key == "kind":
            if meta.get("kind") not in vals:
                return False
        elif key in ("path", "name"):
            hay = meta.get("path", "").lower()
            base = hay.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            target = base if key == "name" else hay
            if not any(v in target for v in vals):
                return False
    return True


def search(index, query: str, *, limit: int = 50, snippet_chars: int = 160,
           max_snippets: int = 3) -> list[Hit]:
    pq = parse(query)
    n_docs = max(index.doc_count(), 1)
    scored: dict[int, float] = {}
    match_pos: dict[int, list[int]] = {}

    if pq.match_all:
        for d in index.all_doc_ids():
            scored[d] = 0.0

    for group in pq.or_groups:
        positives = [a for a in group if not a.negate]
        negatives = [a for a in group if a.negate]
        if not positives:
            raise QueryError("a query group needs at least one positive term")
        group_docs = None
        group_hits: dict[int, list[int]] = {}
        group_score: dict[int, float] = {}
        for atom in positives:
            docs = _atom_docs(index, atom)
            idf = math.log(1 + n_docs / (1 + len(docs)))
            for d, ps in docs.items():
                group_score[d] = group_score.get(d, 0) + len(ps) * idf
                group_hits.setdefault(d, []).extend(ps)
            ids = set(docs)
            group_docs = ids if group_docs is None else group_docs & ids
        if group_docs is None:
            continue
        for atom in negatives:
            group_docs -= set(_atom_docs(index, atom))
        for d in group_docs:
            scored[d] = max(scored.get(d, 0), group_score.get(d, 0))
            match_pos.setdefault(d, []).extend(sorted(group_hits.get(d, [])))

    ranked = sorted(scored.items(), key=lambda kv: -kv[1])
    hits: list[Hit] = []
    for doc_id, score in ranked:
        meta = index.doc_meta(doc_id)
        if not meta or not _pass_filters(meta, pq.filters):
            continue
        positions = sorted(set(match_pos.get(doc_id, [])))
        hit = Hit(path=meta["path"], score=round(score, 3),
                  matches=len(positions), kind=meta.get("kind", ""),
                  size=meta.get("size", 0))
        if max_snippets:
            hit.snippets = _snippets(meta["path"], positions, snippet_chars,
                                     max_snippets)
        hits.append(hit)
        if len(hits) >= limit:
            break
    return hits


def _snippets(path: str, positions: list[int], width: int, count: int):
    if not positions:
        return []
    try:
        text, _ = extract(Path(path), max_size=64 * 1024 * 1024)
    except OSError:
        return []
    off_by_pos = {}
    for _tok, pos, off in tokens(text):
        if pos in positions:
            off_by_pos[pos] = off
        if len(off_by_pos) == len(positions):
            break
    out = []
    used = []
    for pos in positions:
        off = off_by_pos.get(pos)
        if off is None:
            continue
        if any(abs(off - u) < width for u in used):
            continue
        used.append(off)
        a = max(0, off - width // 2)
        b = min(len(text), off + width // 2)
        frag = " ".join(text[a:b].split())
        out.append(("… " if a else "") + frag + (" …" if b < len(text) else ""))
        if len(out) >= count:
            break
    return out
