"""SPDX 许可证表达式解析器。

支持 SPDX v2.1 Annex D 的 AND / OR / WITH 语法：

    SPDXLicenseExpression := AndTerm (OR AndTerm)*
    AndTerm               := WithTerm (AND WithTerm)*
    WithTerm              := Term (WITH Identifier)?
    Term                  := '(' SPDXLicenseExpression ')'
                            | LicenseIdentifier ['+']
                            | LicenseRef([:...])
                            | DocumentRef(...):LicenseRef(...)

并额外容忍生态中常见的非标准写法：
    "GPL-2.0"      -> "GPL-2.0-only"（SPDX v2 以前的旧标识符）
    "MIT OR Apache-2.0" 之外，也接受 "MIT/Apache-2.0"（Rust crate 常见）
    "Proprietary" 作为自定义 LicenseRef-Proprietary
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(\(|\))"                       # 1 括号
    r"|(?i:\b(AND|OR|WITH)\b)"       # 2 关键字
    r"|(/)"                          # 3 旧式 "/" OR
    r"|([A-Za-z0-9.\-+_:]+)"         # 4 标识符
    r")"
)

_KEYWORDS = {"AND", "OR", "WITH"}


class NodeKind(str, Enum):
    LICENSE = "license"
    WITH = "with"
    AND = "and"
    OR = "or"


@dataclass(frozen=True)
class LicenseNode:
    """表达式 AST 节点。"""

    kind: NodeKind
    # LICENSE 节点上的许可证 id（已规范化，如 GPL-2.0-only）
    spdx_id: str | None = None
    # WITH 节点上的例外 id（如 Classpath-exception-2.0）
    exception: str | None = None
    # WITH / AND / OR 的子节点
    children: tuple["LicenseNode", ...] = field(default_factory=tuple)
    # 无法识别为标准 SPDX id（LicenseRef、拼写错误等）
    unknown: bool = False

    def leaves(self) -> list["LicenseNode"]:
        if self.kind is NodeKind.LICENSE:
            return [self]
        result: list[LicenseNode] = []
        for child in self.children:
            result.extend(child.leaves())
        return result


class ExpressionError(ValueError):
    """SPDX 表达式语法错误。"""


@dataclass
class _Token:
    text: str
    kind: str  # '(' ')' 'AND' 'OR' 'WITH' '/' 'ID'


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise ExpressionError(f"无法解析的许可证表达式: {text[pos:]!r}")
        pos = m.end()
        if m.group(1):
            tokens.append(_Token(m.group(1), m.group(1)))
        elif m.group(2):
            tokens.append(_Token(m.group(2).upper(), m.group(2).upper()))
        elif m.group(3):
            tokens.append(_Token("/", "OR"))
        else:
            ident = m.group(4)
            if ident.upper() in _KEYWORDS:  # 大小写不敏感的关键字
                tokens.append(_Token(ident.upper(), ident.upper()))
            else:
                tokens.append(_Token(ident, "ID"))
    return tokens


# SPDX v2 之前没有 -only/-or-later 后缀，仅 GNU 家族的裸版本号按 -only 处理
_GNU_BARE_RE = re.compile(r"^(?:AGPL|LGPL|GPL)-\d+\.\d+$")


def normalize_id(raw: str) -> str:
    """规范化许可证 id：处理 '+' 后缀、裸版本号、常见别名。"""
    if raw in ("Proprietary", "proprietary", "PROPRIETARY"):
        return "LicenseRef-Proprietary"
    if raw.startswith(("LicenseRef-", "DocumentRef-")):
        return raw

    plus = raw.endswith("+")
    ident = raw[:-1] if plus else raw

    if _GNU_BARE_RE.match(ident):
        ident = f"{ident}-only"

    if plus:
        # LGPL-2.1+ / GPL-3.0+ -> -or-later
        if ident.endswith("-only"):
            ident = ident[: -len("-only")] + "-or-later"
        elif re.match(r"^(?:AGPL|LGPL|GPL)-\d+\.\d+$", ident):
            ident = ident + "-or-later"

    return ident


class _Parser:
    def __init__(self, tokens: list[_Token], raw: str):
        self.tokens = tokens
        self.raw = raw
        self.pos = 0

    def _peek(self) -> _Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> _Token:
        tok = self._peek()
        if tok is None:
            raise ExpressionError(f"许可证表达式意外结束: {self.raw!r}")
        self.pos += 1
        return tok

    def parse(self) -> LicenseNode:
        if not self.tokens:
            raise ExpressionError("空的许可证表达式")
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise ExpressionError(f"许可证表达式存在多余 token: {self.raw!r}")
        return node

    def _parse_or(self) -> LicenseNode:
        left = self._parse_and()
        children = [left]
        while self._peek() and self._peek().kind == "OR":
            self._next()
            children.append(self._parse_and())
        if len(children) == 1:
            return left
        return LicenseNode(kind=NodeKind.OR, children=tuple(children))

    def _parse_and(self) -> LicenseNode:
        left = self._parse_with()
        children = [left]
        while self._peek() and self._peek().kind == "AND":
            self._next()
            children.append(self._parse_with())
        if len(children) == 1:
            return left
        return LicenseNode(kind=NodeKind.AND, children=tuple(children))

    def _parse_with(self) -> LicenseNode:
        term = self._parse_term()
        if self._peek() and self._peek().kind == "WITH":
            self._next()
            tok = self._next()
            if tok.kind != "ID":
                raise ExpressionError(f"WITH 后期望例外标识符，得到 {tok.text!r}")
            return LicenseNode(
                kind=NodeKind.WITH, exception=tok.text, children=(term,)
            )
        return term

    def _parse_term(self) -> LicenseNode:
        tok = self._next()
        if tok.kind == "(":
            inner = self._parse_or()
            closing = self._next()
            if closing.kind != ")":
                raise ExpressionError("许可证表达式缺少右括号 ')'")
            return inner
        if tok.kind != "ID":
            raise ExpressionError(f"许可证表达式期望许可证 id，得到 {tok.text!r}")
        spdx_id = normalize_id(tok.text)
        unknown = spdx_id.startswith(("LicenseRef-", "DocumentRef-"))
        return LicenseNode(kind=NodeKind.LICENSE, spdx_id=spdx_id, unknown=unknown)


def parse_expression(text: str) -> LicenseNode:
    """把 SPDX 许可证表达式字符串解析成 AST。

    抛出 ExpressionError 描述语法问题。
    """
    if text is None or not str(text).strip():
        raise ExpressionError("许可证表达式为空")
    return _Parser(_tokenize(str(text).strip()), str(text).strip()).parse()
