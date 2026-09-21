import pytest

from app.spdx import ExpressionError, NodeKind, parse_expression


def test_parse_simple_and_or_with():
    node = parse_expression("MIT AND Apache-2.0")
    assert node.kind is NodeKind.AND
    assert [l.spdx_id for l in node.leaves()] == ["MIT", "Apache-2.0"]

    node = parse_expression("(MIT OR Apache-2.0) WITH Classpath-exception-2.0")
    # WITH 直接作用于括号表达式：叶子都携带同一例外
    assert node.kind is NodeKind.WITH
    assert node.exception == "Classpath-exception-2.0"
    assert len(node.leaves()) == 2

    node = parse_expression("GPL-2.0-only WITH Classpath-exception-2.0 OR MIT")
    assert node.kind is NodeKind.OR
    assert node.children[0].kind is NodeKind.WITH


def test_parse_normalizes_legacy_identifiers():
    assert parse_expression("GPL-2.0").leaves()[0].spdx_id == "GPL-2.0-only"
    assert parse_expression("LGPL-2.1+").leaves()[0].spdx_id == "LGPL-2.1-or-later"
    assert parse_expression("GPL-3.0+").leaves()[0].spdx_id == "GPL-3.0-or-later"


def test_parse_legacy_slash_dual_license():
    node = parse_expression("MIT/Apache-2.0")
    assert node.kind is NodeKind.OR
    assert [l.spdx_id for l in node.leaves()] == ["MIT", "Apache-2.0"]


def test_parse_case_insensitive_keywords():
    node = parse_expression("mit or Apache-2.0 and BSD-3-Clause")
    assert node.kind is NodeKind.OR  # AND 结合优先级高于 OR
    assert node.children[1].kind is NodeKind.AND


def test_parse_license_ref():
    node = parse_expression("LicenseRef-Proprietary")
    leaf = node.leaves()[0]
    assert leaf.unknown is True
    assert leaf.spdx_id == "LicenseRef-Proprietary"

    node2 = parse_expression("Proprietary")
    assert node2.leaves()[0].spdx_id == "LicenseRef-Proprietary"


def test_parse_errors():
    with pytest.raises(ExpressionError):
        parse_expression("")
    with pytest.raises(ExpressionError):
        parse_expression("MIT AND")
    with pytest.raises(ExpressionError):
        parse_expression("MIT OR (Apache-2.0")
    with pytest.raises(ExpressionError):
        parse_expression("MIT WITH")
