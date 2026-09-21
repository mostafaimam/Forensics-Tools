"""Tokenize and parse a YARA-subset ``condition:`` expression into an AST,
then evaluate it against a per-rule match context.

Grammar (informal)::

    expr       := or_expr
    or_expr    := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | compare
    compare    := value (("<"|"<="|">"|">="|"=="|"!=") value)?
                | primary
    value      := "#" IDENT | "filesize" | NUMBER
    primary    := "(" expr ")" | "true" | "false"
                | ("any"|"all"|NUMBER) "of" set_ref
                | "$" IDENT
    set_ref    := "them" | "(" "$" IDENT ("," "$" IDENT)* ")"

Not supported (raises RuleSyntaxError): string offsets (``@id``),
wildcarded string-set references (``$a*``), module/PE-specific
identifiers, ``for`` loops, arithmetic beyond simple comparisons.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from memory_yara.rules import RuleSyntaxError

_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<num>\d+(?:KB|MB)?) |
        (?P<hashid>\#\w+) |
        (?P<dollarid>\$\w+) |
        (?P<ident>[A-Za-z_]\w*) |
        (?P<op><=|>=|==|!=|<|>|\(|\)|,)
    )""", re.VERBOSE | re.IGNORECASE)

_COMPARATORS = {"<", "<=", ">", ">=", "==", "!="}


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise RuleSyntaxError(f"unexpected character in condition: "
                                  f"{text[pos:pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup
        tokens.append((kind, m.group(kind)))
    tokens.append(("eof", ""))
    return tokens


@dataclass
class BoolLit:
    value: bool


@dataclass
class StringRef:
    id: str


@dataclass
class Not:
    expr: object


@dataclass
class BoolOp:
    op: str                 # "and" | "or"
    parts: list


@dataclass
class OfExpr:
    count: object            # "all" | "any" | int
    ids: list                # list[str] or "them"


@dataclass
class CountValue:
    id: str


@dataclass
class FileSizeValue:
    pass


@dataclass
class IntLit:
    value: int


@dataclass
class Compare:
    left: object
    op: str
    right: object


def _int_with_suffix(s: str) -> int:
    s = s.upper()
    if s.endswith("KB"):
        return int(s[:-2]) * 1024
    if s.endswith("MB"):
        return int(s[:-2]) * 1024 * 1024
    return int(s)


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]], known_ids: set[str]):
        self.tokens = tokens
        self.pos = 0
        self.known_ids = known_ids

    def _peek(self):
        return self.tokens[self.pos]

    def _next(self):
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def _expect_ident(self, word: str):
        kind, val = self._next()
        if kind != "ident" or val.lower() != word:
            raise RuleSyntaxError(f"expected {word!r}, got {val!r}")

    def _check_id(self, ident: str):
        if ident not in self.known_ids:
            raise RuleSyntaxError(f"condition refers to undefined string "
                                  f"{ident!r}")

    def parse(self):
        node = self._or_expr()
        kind, val = self._peek()
        if kind != "eof":
            raise RuleSyntaxError(f"unexpected trailing input near {val!r}")
        return node

    def _or_expr(self):
        parts = [self._and_expr()]
        while self._peek()[0] == "ident" and self._peek()[1].lower() == "or":
            self._next()
            parts.append(self._and_expr())
        return parts[0] if len(parts) == 1 else BoolOp("or", parts)

    def _and_expr(self):
        parts = [self._not_expr()]
        while (self._peek()[0] == "ident" and
               self._peek()[1].lower() == "and"):
            self._next()
            parts.append(self._not_expr())
        return parts[0] if len(parts) == 1 else BoolOp("and", parts)

    def _not_expr(self):
        if self._peek()[0] == "ident" and self._peek()[1].lower() == "not":
            self._next()
            return Not(self._not_expr())
        return self._compare()

    def _compare(self):
        # "N of (...)" starts with a NUMBER too - try that reading first
        # so a bare integer isn't mistaken for a filesize/count operand.
        if self._peek()[0] == "num":
            save = self.pos
            self._next()
            is_of = (self._peek()[0] == "ident" and
                    self._peek()[1].lower() == "of")
            self.pos = save
            if is_of:
                return self._primary()
        start = self.pos
        try:
            left = self._value()
        except RuleSyntaxError:
            self.pos = start
            return self._primary()
        if self._peek()[0] == "op" and self._peek()[1] in _COMPARATORS:
            op = self._next()[1]
            right = self._value()
            return Compare(left, op, right)
        if isinstance(left, (CountValue, FileSizeValue, IntLit)):
            raise RuleSyntaxError("a bare count/filesize value is not a "
                                  "valid boolean condition")
        return left

    def _value(self):
        kind, val = self._peek()
        if kind == "hashid":
            self._next()
            ident = "$" + val[1:]
            self._check_id(ident)
            return CountValue(ident)
        if kind == "ident" and val.lower() == "filesize":
            self._next()
            return FileSizeValue()
        if kind == "num":
            self._next()
            return IntLit(_int_with_suffix(val))
        raise RuleSyntaxError(f"expected a value, got {val!r}")

    def _primary(self):
        kind, val = self._peek()
        if kind == "op" and val == "(":
            self._next()
            node = self._or_expr()
            if not (self._peek()[0] == "op" and self._peek()[1] == ")"):
                raise RuleSyntaxError("expected ')'")
            self._next()
            return node
        if kind == "ident" and val.lower() in ("true", "false"):
            self._next()
            return BoolLit(val.lower() == "true")
        if kind == "dollarid":
            self._next()
            ident = "$" + val[1:]
            self._check_id(ident)
            return StringRef(ident)
        if kind == "ident" and val.lower() in ("any", "all"):
            self._next()
            self._expect_ident("of")
            return OfExpr(val.lower(), self._set_ref())
        if kind == "num":
            self._next()
            self._expect_ident("of")
            return OfExpr(int(val), self._set_ref())
        raise RuleSyntaxError(f"unexpected token in condition: {val!r}")

    def _set_ref(self):
        kind, val = self._peek()
        if kind == "ident" and val.lower() == "them":
            self._next()
            return "them"
        if kind == "op" and val == "(":
            self._next()
            ids = []
            while True:
                k, v = self._next()
                if k != "dollarid":
                    raise RuleSyntaxError(f"expected a $string in string "
                                          f"set, got {v!r}")
                ids.append("$" + v[1:])
                self._check_id(ids[-1])
                k2, v2 = self._peek()
                if k2 == "op" and v2 == ",":
                    self._next()
                    continue
                break
            if not (self._peek()[0] == "op" and self._peek()[1] == ")"):
                raise RuleSyntaxError("expected ')' after string set")
            self._next()
            return ids
        raise RuleSyntaxError("expected 'them' or a ($a, $b, ...) set")


def parse_condition(text: str, known_ids: set[str]):
    tokens = _tokenize(text)
    return _Parser(tokens, known_ids).parse()


class MatchContext:
    def __init__(self, counts: dict, filesize: int):
        self._counts = counts
        self.filesize = filesize

    def matched(self, ident: str) -> bool:
        return self._counts.get(ident, 0) > 0

    def count(self, ident: str) -> int:
        return self._counts.get(ident, 0)

    def all_ids(self) -> list:
        return list(self._counts.keys())


def _value_of(node, ctx: MatchContext) -> int:
    if isinstance(node, IntLit):
        return node.value
    if isinstance(node, CountValue):
        return ctx.count(node.id)
    if isinstance(node, FileSizeValue):
        return ctx.filesize
    raise RuleSyntaxError(f"not a value expression: {node!r}")


_OPS = {
    "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b, "!=": lambda a, b: a != b,
}


def evaluate(node, ctx: MatchContext) -> bool:
    if isinstance(node, BoolLit):
        return node.value
    if isinstance(node, StringRef):
        return ctx.matched(node.id)
    if isinstance(node, Not):
        return not evaluate(node.expr, ctx)
    if isinstance(node, BoolOp):
        vals = (evaluate(p, ctx) for p in node.parts)
        return all(vals) if node.op == "and" else any(vals)
    if isinstance(node, Compare):
        return _OPS[node.op](_value_of(node.left, ctx),
                             _value_of(node.right, ctx))
    if isinstance(node, OfExpr):
        ids = ctx.all_ids() if node.ids == "them" else node.ids
        hits = sum(1 for i in ids if ctx.matched(i))
        if node.count == "any":
            return hits >= 1
        if node.count == "all":
            return hits == len(ids)
        return hits >= node.count
    raise RuleSyntaxError(f"cannot evaluate node: {node!r}")
