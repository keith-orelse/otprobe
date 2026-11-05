"""Condition language for rules-as-data (docs/RULES.md §2). Hand-written parser; never uses eval()."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


class ConditionSyntaxError(ValueError):
    pass


class ConditionTypeError(TypeError):
    pass


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING: Any = _Missing()

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<string>'(?:[^'\\]|\\.)*')
     |(?P<number>-?\d+(?:\.\d+)?)
     |(?P<param>\$[a-z_][a-z0-9_]*)
     |(?P<op>==|!=|<=|>=|<|>)
     |(?P<punct>[\[\],])
     |(?P<word>[A-Za-z_]+)
    )""", re.X)

CMP_OPS = {"==", "!=", "<", "<=", ">", ">="}


@dataclass(frozen=True)
class Operand:
    kind: str          # literal | param | list
    value: Any


@dataclass(frozen=True)
class Clause:
    op: str            # cmp op | in | contains | intersects | matches | empty
    negate: bool = False
    count: bool = False
    operand: Operand | None = None


@dataclass(frozen=True)
class Condition:
    source: str
    disjuncts: tuple[tuple[Clause, ...], ...]

    def params(self) -> set[str]:
        out: set[str] = set()

        def walk(o: Operand | None) -> None:
            if o is None:
                return
            if o.kind == "param":
                out.add(o.value)
            elif o.kind == "list":
                for item in o.value:
                    walk(item)

        for conj in self.disjuncts:
            for c in conj:
                walk(c.operand)
        return out


def _tokenize(text: str) -> list[tuple[str, str]]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ConditionSyntaxError(f"unexpected input at {pos}: {text[pos:pos + 12]!r}")
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = _tokenize(text)
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise ConditionSyntaxError(f"unexpected end of condition: {self.text!r}")
        self.i += 1
        return tok

    def word(self, w: str) -> bool:
        tok = self.peek()
        if tok and tok[0] == "word" and tok[1].lower() == w:
            self.i += 1
            return True
        return False

    def expect_word(self, w: str) -> None:
        if not self.word(w):
            raise ConditionSyntaxError(f"expected '{w}' in {self.text!r}")

    def parse(self) -> Condition:
        disjuncts = [self.conjunction()]
        while self.word("or"):
            disjuncts.append(self.conjunction())
        if self.peek() is not None:
            raise ConditionSyntaxError(f"trailing input in {self.text!r}")
        return Condition(self.text, tuple(disjuncts))

    def conjunction(self) -> tuple[Clause, ...]:
        clauses = [self.clause()]
        while self.word("and"):
            clauses.append(self.clause())
        return tuple(clauses)

    def clause(self) -> Clause:
        count = self.word("count")
        tok = self.peek()
        if tok and tok[0] == "op":
            self.take()
            return Clause(tok[1], count=count, operand=self.operand())
        if count:
            raise ConditionSyntaxError("'count' must be followed by a comparison")
        if self.word("is"):
            negate = self.word("not")
            self.expect_word("empty")
            return Clause("empty", negate=negate)
        negate = self.word("not")
        for kw in ("in", "contains", "intersects"):
            if self.word(kw):
                return Clause(kw, negate=negate, operand=self.operand())
        if self.word("matches"):
            op = self.operand()
            if op.kind != "literal" or not isinstance(op.value, str):
                raise ConditionSyntaxError("'matches' needs a string pattern")
            re.compile(op.value)
            return Clause("matches", negate=negate, operand=op)   # "not matches": no element matches
        raise ConditionSyntaxError(f"cannot parse clause in {self.text!r}")

    def operand(self) -> Operand:
        kind, val = self.take()
        if kind == "string":
            return Operand("literal", re.sub(r"\\(.)", r"\1", val[1:-1]))
        if kind == "number":
            return Operand("literal", float(val) if "." in val else int(val))
        if kind == "param":
            return Operand("param", val[1:])
        if kind == "word" and val.lower() in ("true", "false"):
            return Operand("literal", val.lower() == "true")
        if kind == "punct" and val == "[":
            items: list[Operand] = []
            if self.peek() == ("punct", "]"):
                self.take()
                return Operand("list", tuple(items))
            while True:
                items.append(self.operand())
                k, v = self.take()
                if (k, v) == ("punct", "]"):
                    return Operand("list", tuple(items))
                if (k, v) != ("punct", ","):
                    raise ConditionSyntaxError(f"expected ',' or ']' in {self.text!r}")
        raise ConditionSyntaxError(f"unexpected token {val!r} in {self.text!r}")


_CACHE: dict[str, Condition] = {}


def parse(text: str) -> Condition:
    cond = _CACHE.get(text)
    if cond is None:
        cond = _CACHE[text] = _Parser(text).parse()
    return cond


def resolve_operand(o: Operand, params: Mapping[str, Any]) -> Any:
    if o.kind == "literal":
        return o.value
    if o.kind == "list":
        return [resolve_operand(i, params) for i in o.value]
    if o.value not in params:
        raise ConditionSyntaxError(f"undefined parameter ${o.value}")
    return params[o.value]


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _compare(op: str, left: Any, right: Any) -> bool:
    if op in ("==", "!="):
        if _is_number(left) and _is_number(right):
            eq = left == right
        elif type(left) is not type(right):
            raise ConditionTypeError(f"cannot compare {type(left).__name__} with {type(right).__name__}")
        else:
            eq = left == right
        return eq if op == "==" else not eq
    if not (_is_number(left) and _is_number(right)):
        raise ConditionTypeError(f"'{op}' needs numbers, got {type(left).__name__} and {type(right).__name__}")
    return {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right}[op]


def _clause(c: Clause, value: Any, params: Mapping[str, Any]) -> bool:
    if c.op == "empty":
        empty = value is MISSING or value is None or value in ("", [], {})
        return not empty if c.negate else empty
    if value is MISSING:
        raise ConditionTypeError("value is missing")
    operand = resolve_operand(c.operand, params) if c.operand else None
    if c.op in CMP_OPS:
        if c.count:
            if not isinstance(value, list):
                raise ConditionTypeError("'count' needs a list")
            return _compare(c.op, len(value), operand)
        if isinstance(value, (list, dict)):
            raise ConditionTypeError(f"'{c.op}' cannot compare a {type(value).__name__}")
        return _compare(c.op, value, operand)
    if c.op == "in":
        if not isinstance(operand, list):
            raise ConditionTypeError("'in' needs a list operand")
        if isinstance(value, (list, dict)):
            raise ConditionTypeError("'in' needs a scalar value")
        result = value in operand
    elif c.op == "contains":
        if isinstance(value, list):
            result = operand in value
        elif isinstance(value, str) and isinstance(operand, str):
            result = operand in value
        else:
            raise ConditionTypeError("'contains' needs a list or string value")
    elif c.op == "intersects":
        if not isinstance(value, list) or not isinstance(operand, list):
            raise ConditionTypeError("'intersects' needs list value and list operand")
        result = any(v in operand for v in value)
    else:  # matches
        values = value if isinstance(value, list) else [value]
        if not all(isinstance(v, str) for v in values):
            raise ConditionTypeError("'matches' needs string values")
        result = any(re.search(operand, v) for v in values)
    return not result if c.negate else result


def evaluate(condition: Condition | str, value: Any, params: Mapping[str, Any] | None = None) -> bool:
    cond = parse(condition) if isinstance(condition, str) else condition
    params = params or {}
    return any(all(_clause(c, value, params) for c in conj) for conj in cond.disjuncts)


def resolve_path(doc: Mapping[str, Any], path: str) -> Any:
    """Resolve 'a.b[].c' against a nested document. Returns MISSING when absent or null."""
    value: Any = doc
    projected = False
    for seg in path.split("."):
        name, is_list = (seg[:-2], True) if seg.endswith("[]") else (seg, False)
        if not projected:
            if not isinstance(value, Mapping) or name not in value:
                return MISSING
            value = value[name]
            if value is None:
                return MISSING
            if is_list:
                if not isinstance(value, list):
                    return MISSING
                projected = True
        else:
            nxt: list[Any] = []
            for item in value:
                if isinstance(item, Mapping) and item.get(name) is not None:
                    v = item[name]
                    nxt.extend(v if is_list and isinstance(v, list) else [v])
            value = nxt
    return value


def nest(flat: Mapping[str, Any]) -> dict[str, Any]:
    """{'os.name': 'x', 'services.winrm.available': True} -> nested dict."""
    out: dict[str, Any] = {}
    for path, value in flat.items():
        cur = out
        parts = path.split(".")
        for p in parts[:-1]:
            nxt = cur.get(p)
            if not isinstance(nxt, dict):
                nxt = cur[p] = {}
            cur = nxt
        cur[parts[-1]] = value
    return out
