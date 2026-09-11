"""Parse and evaluate a Sigma `condition` expression.

Grammar (the common subset): identifiers (selection names, optionally
wildcarded: ``selection*``), ``and`` / ``or`` / ``not``, parentheses, and
the aggregate forms ``1 of <name-or-wildcard>`` / ``all of
<name-or-wildcard>`` (``them`` means every selection in the rule).
"""

from __future__ import annotations

import fnmatch
import re

_TOKEN = re.compile(
    r"\(|\)|\bnot\b|\band\b|\bor\b|\ball\s+of\b|\b\d+\s+of\b|[A-Za-z_][\w*]*",
    re.I)


class ConditionError(ValueError):
    pass


def tokenize(expr: str) -> list[str]:
    pos = 0
    out = []
    while pos < len(expr):
        if expr[pos].isspace():
            pos += 1
            continue
        m = _TOKEN.match(expr, pos)
        if not m:
            raise ConditionError(f"unexpected character at: {expr[pos:]!r}")
        out.append(m.group(0))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, tokens, names):
        self.toks = tokens
        self.i = 0
        self.names = names

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def eat(self, expect=None):
        t = self.peek()
        if expect and (t is None or t.lower() != expect):
            raise ConditionError(f"expected {expect!r}, got {t!r}")
        self.i += 1
        return t

    def parse(self):
        node = self.or_expr()
        if self.i != len(self.toks):
            raise ConditionError(f"trailing tokens: {self.toks[self.i:]}")
        return node

    def or_expr(self):
        left = self.and_expr()
        while self.peek() and self.peek().lower() == "or":
            self.eat()
            right = self.and_expr()
            left = ("or", left, right)
        return left

    def and_expr(self):
        left = self.not_expr()
        while self.peek() and self.peek().lower() == "and":
            self.eat()
            right = self.not_expr()
            left = ("and", left, right)
        return left

    def not_expr(self):
        if self.peek() and self.peek().lower() == "not":
            self.eat()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self):
        t = self.peek()
        if t is None:
            raise ConditionError("unexpected end of condition")
        if t == "(":
            self.eat("(")
            node = self.or_expr()
            self.eat(")")
            return node
        low = t.lower()
        if low.endswith(" of") or re.match(r"^\d+\s+of$", low) or \
                low == "all of":
            self.eat()
            target = self.eat()
            n = "all" if low.startswith("all") else int(low.split()[0])
            return ("nof", n, target)
        self.eat()
        return ("name", t)


def parse(expr: str, names) -> tuple:
    return _Parser(tokenize(expr), names).parse()


def _matching_names(pattern: str, names) -> list[str]:
    if pattern == "them":
        return list(names)
    if "*" in pattern:
        return [n for n in names if fnmatch.fnmatch(n, pattern)]
    return [pattern] if pattern in names else []


def evaluate(node, results: dict, names) -> bool:
    kind = node[0]
    if kind == "name":
        return bool(results.get(node[1], False))
    if kind == "not":
        return not evaluate(node[1], results, names)
    if kind == "and":
        return evaluate(node[1], results, names) and \
            evaluate(node[2], results, names)
    if kind == "or":
        return evaluate(node[1], results, names) or \
            evaluate(node[2], results, names)
    if kind == "nof":
        n, pattern = node[1], node[2]
        matched = _matching_names(pattern, names)
        hits = sum(1 for m in matched if results.get(m, False))
        need = len(matched) if n == "all" else n
        return hits >= need and hits > 0
    raise ConditionError(f"bad node: {node}")
