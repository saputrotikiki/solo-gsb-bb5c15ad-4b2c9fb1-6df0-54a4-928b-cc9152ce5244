"""SPDX 表达式解析器测试。"""
import pytest

from app.spdx import (
    And,
    License,
    Or,
    SPDXParseError,
    dnf_groups,
    parse_spdx,
)


def test_simple_license_with_plus_normalized():
    node = parse_spdx("GPL-2.0+")
    assert node == License("GPL-2.0-or-later")


def test_bare_version_aliases():
    assert parse_spdx("GPL-3.0") == License("GPL-3.0-only")
    assert parse_spdx("LGPL-2.1") == License("LGPL-2.1-only")


def test_with_exception():
    node = parse_spdx("GPL-2.0-only WITH Classpath-exception-2.0")
    assert node == License("GPL-2.0-only", "Classpath-exception-2.0")


def test_and_or_precedence():
    node = parse_spdx("MIT OR Apache-2.0 AND GPL-3.0-only")
    assert isinstance(node, Or)
    assert node.left == License("MIT")
    assert isinstance(node.right, And)


def test_parentheses():
    node = parse_spdx("(MIT OR Apache-2.0) AND GPL-3.0-only")
    assert isinstance(node, And)
    assert isinstance(node.left, Or)


def test_unknown_plus_kept():
    node = parse_spdx("Weird-1.0+")
    assert node.spdx_id == "Weird-1.0+"


def test_license_ref():
    node = parse_spdx("DocumentRef-oss:LicenseRef-Proprietary")
    assert node.spdx_id == "DocumentRef-oss:LicenseRef-Proprietary"


def test_none_and_noassertion():
    assert parse_spdx("NONE") == License("NONE")
    assert parse_spdx("NOASSERTION") == License("NOASSERTION")


@pytest.mark.parametrize("text", [
    "", "MIT AND", "OR MIT", "(MIT", "MIT)", "MIT WITH",
    "NONE WITH Classpath-exception-2.0", "MIT @ Apache-2.0",
])
def test_parse_errors(text):
    with pytest.raises(SPDXParseError):
        parse_spdx(text)


def test_dnf_groups_and_label():
    node = parse_spdx("(MIT OR Apache-2.0) AND (LGPL-2.1-only OR MPL-2.0)")
    groups = dnf_groups(node)
    assert len(groups) == 4
    assert {len(g) for g in groups} == {2}
    assert "OR" in node.label
