"""SPDX 许可证表达式解析器。

支持的子集（基于 SPDX Annex IV 许可证表达式语法）：

    expr   := term (OR term)*   （OR 优先级最低）
    term   := factor (AND factor)*
    factor := LPAREN expr RPAREN
            | ident [WITH ident] ['+']
    ident  := 许可证标识 / LicenseRef-... / DocumentRef-...:LicenseRef-...

AND / OR / WITH 为保留关键字（大写），可被小写许可证标识包含的连字符不会误判。
``+`` 后缀归一化为常见的 ``-or-later`` SPDX 标识；``NONE`` 与 ``NOASSERTION``
作为原子值支持。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Union

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<paren>[()])"
    r"|(?P<op>AND|OR|WITH)"
    r"|(?P<plus>\+)"
    r"|(?P<ident>[A-Za-z0-9][A-Za-z0-9.\-]*(?::[A-Za-z0-9][A-Za-z0-9.\-]*)?)"
    r")"
)

# “裸版本号 + +” 到现代 SPDX -or-later 标识的归一化映射。
PLUS_NORMALIZE = {
    "GPL-1.0": "GPL-1.0-or-later",
    "GPL-2.0": "GPL-2.0-or-later",
    "GPL-3.0": "GPL-3.0-or-later",
    "LGPL-2.0": "LGPL-2.0-or-later",
    "LGPL-2.1": "LGPL-2.1-or-later",
    "LGPL-3.0": "LGPL-3.0-or-later",
    "AGPL-3.0": "AGPL-3.0-or-later",
}

# 已弃用标识的兼容别名。
ALIASES = {
    "GPL-1.0+": "GPL-1.0-or-later",
    "GPL-2.0+": "GPL-2.0-or-later",
    "GPL-2.0+": "GPL-2.0-or-later",
    "GPL-3.0+": "GPL-3.0-or-later",
    "LGPL-2.0+": "LGPL-2.0-or-later",
    "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPL-3.0+": "AGPL-3.0-or-later",
    "GPL-2.0": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "LGPL-2.0": "LGPL-2.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
}

SPECIAL_ATOMS = {"NONE", "NOASSERTION"}


class SPDXParseError(ValueError):
    """SPDX 表达式解析失败，message 中携带出错位置。"""

    def __init__(self, message: str, pos: int):
        super().__init__(f"SPDX 表达式错误（位置 {pos}）：{message}")
        self.pos = pos


@dataclass(frozen=True)
class License:
    """单个许可证叶子：SPDXID [WITH Exception] [+]（归一化后无 +）。"""

    spdx_id: str
    exception: Union[str, None] = None

    @property
    def label(self) -> str:
        if self.exception:
            return f"{self.spdx_id} WITH {self.exception}"
        return self.spdx_id

    def leaves(self) -> list["License"]:
        return [self]


@dataclass(frozen=True)
class And:
    left: "Node"
    right: "Node"

    @property
    def label(self) -> str:
        return f"({self.left.label} AND {self.right.label})"

    def leaves(self) -> list[License]:
        return self.left.leaves() + self.right.leaves()


@dataclass(frozen=True)
class Or:
    left: "Node"
    right: "Node"

    @property
    def label(self) -> str:
        return f"({self.left.label} OR {self.right.label})"

    def leaves(self) -> list[License]:
        return self.left.leaves() + self.right.leaves()


Node = Union[License, And, Or]


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    pos: int


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise SPDXParseError(f"无法识别的字符 {text[pos]!r}", pos)
        if m.group("paren"):
            tokens.append(_Token("paren", m.group("paren"), m.start()))
        elif m.group("op"):
            tokens.append(_Token("op", m.group("op"), m.start()))
        elif m.group("plus"):
            tokens.append(_Token("plus", "+", m.start()))
        else:
            tokens.append(_Token("ident", m.group("ident"), m.start()))
        pos = m.end()
    return tokens


def _normalize_id(raw: str, plus: bool) -> str:
    ident = raw
    if plus:
        ident = PLUS_NORMALIZE.get(ident, f"{ident}+")
    # 仅在没有 + 时套用裸版本号别名；PLUS_NORMALIZE 已处理带 + 情况。
    if not plus and ident in ALIASES:
        ident = ALIASES[ident]
    return ident


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.tokens = _tokenize(text)
        self.i = 0

    def _peek(self) -> Union[_Token, None]:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _next(self) -> _Token:
        tok = self._peek()
        if tok is None:
            raise SPDXParseError("表达式意外结束", len(self.text))
        self.i += 1
        return tok

    def parse(self) -> Node:
        if not self.tokens:
            raise SPDXParseError("表达式为空", 0)
        node = self._parse_or()
        if self._peek() is not None:
            tok = self._peek()
            raise SPDXParseError(f"存在多余记号 {tok.value!r}", tok.pos)
        return node

    def _parse_or(self) -> Node:
        node = self._parse_and()
        while (tok := self._peek()) and tok.kind == "op" and tok.value == "OR":
            self._next()
            node = Or(node, self._parse_and())
        return node

    def _parse_and(self) -> Node:
        node = self._parse_factor()
        while (tok := self._peek()) and tok.kind == "op" and tok.value == "AND":
            self._next()
            node = And(node, self._parse_factor())
        return node

    def _parse_factor(self) -> Node:
        tok = self._peek()
        if tok is None:
            raise SPDXParseError("缺少许可证标识", len(self.text))
        if tok.kind == "paren" and tok.value == "(":
            self._next()
            node = self._parse_or()
            close = self._peek()
            if close is None or close.kind != "paren" or close.value != ")":
                raise SPDXParseError("缺少右括号 ')'", tok.pos)
            self._next()
            return node
        if tok.kind != "ident":
            raise SPDXParseError(f"期望许可证标识，却得到 {tok.value!r}", tok.pos)
        self._next()
        raw = tok.value
        # + 后缀（仅允许直接跟在标识后）
        plus = False
        nxt = self._peek()
        if nxt and nxt.kind == "plus":
            plus = True
            self._next()
        spdx_id = _normalize_id(raw, plus)
        if spdx_id in SPECIAL_ATOMS:
            # NONE / NOASSERTION 不允许再组合。
            nxt2 = self._peek()
            if nxt2 and nxt2.kind == "op" and nxt2.value == "WITH":
                raise SPDXParseError(f"{spdx_id} 不能搭配 WITH 例外", nxt2.pos)
            return License(spdx_id)
        # WITH 例外
        exception = None
        nxt = self._peek()
        if nxt and nxt.kind == "op" and nxt.value == "WITH":
            self._next()
            exc_tok = self._peek()
            if exc_tok is None or exc_tok.kind != "ident":
                raise SPDXParseError("WITH 后必须是例外标识符", nxt.pos)
            self._next()
            exception = exc_tok.value
        return License(spdx_id, exception)


def parse_spdx(expression: str) -> Node:
    """解析 SPDX 许可证表达式为 AST。失败抛出 :class:`SPDXParseError`。"""
    return _Parser(expression.strip()).parse()


def dnf_groups(node: Node) -> list[list[License]]:
    """将 AST 展开为析取范式：返回 AND 叶子组列表，组间为 OR。

    重复组按标签去重并保持稳定顺序，用于枚举项目发布许可的每个可选分支。
    """
    if isinstance(node, License):
        groups: list[list[License]] = [[node]]
    elif isinstance(node, Or):
        groups = dnf_groups(node.left) + dnf_groups(node.right)
    else:  # And：左右 DNF 的笛卡尔积
        groups = []
        for lg in dnf_groups(node.left):
            for rg in dnf_groups(node.right):
                groups.append(lg + rg)
    seen: set[str] = set()
    unique: list[list[License]] = []
    for group in groups:
        key = " AND ".join(sorted(leaf.label for leaf in group))
        if key not in seen:
            seen.add(key)
            unique.append(group)
    return unique
