from app.audit import LinkType, Severity, pair_verdict
from app.spdx import parse_expression
from app.audit import evaluate_expression


def v(project, component, exception=None, link=LinkType.DYNAMIC):
    return pair_verdict(project, component, exception, link).severity


class TestPermissive:
    def test_mit_into_anything(self):
        assert v("MIT", "Apache-2.0") is None
        assert v("GPL-3.0-only", "MIT") is None
        assert v("AGPL-3.0-only", "BSD-3-Clause") is None

    def test_apache_into_gpl2_conflict(self):
        verdict = pair_verdict("GPL-2.0-only", "Apache-2.0", None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.CONFLICT
        assert verdict.reason == "patent-clause-conflict"
        assert "§7" in verdict.clause or "7" in verdict.clause

    def test_apache_into_gpl3_compatible(self):
        assert v("GPL-3.0-only", "Apache-2.0") is None


class TestWeakCopyleft:
    def test_lgpl_into_mit_conflict(self):
        verdict = pair_verdict("MIT", "LGPL-2.1-only", None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.CONFLICT
        assert verdict.reason == "weak-copyleft-subllicensing"

    def test_lgpl3_dynamic_into_gpl3_warning(self):
        verdict = pair_verdict("GPL-3.0-only", "LGPL-3.0-only", None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.WARNING
        assert verdict.reason == "weak-copyleft-dynamic-link"

    def test_lgpl3_static_into_gpl3_warning(self):
        verdict = pair_verdict("GPL-3.0-only", "LGPL-3.0-only", None, LinkType.STATIC)
        assert verdict.severity is Severity.WARNING
        assert verdict.reason == "weak-copyleft-static-link"

    def test_lgpl21_only_into_gpl3_conflict(self):
        verdict = pair_verdict("GPL-3.0-only", "LGPL-2.1-only", None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.CONFLICT
        assert verdict.reason == "weak-gpl-incompatible"

    def test_lgpl21_or_later_into_gpl3_warning(self):
        assert v("GPL-3.0-only", "LGPL-2.1-or-later") is Severity.WARNING

    def test_classpath_exception_downgrades_gpl(self):
        # GPL-2.0-only + Classpath 例外进入 MIT 项目：降级为弱 copyleft 冲突
        verdict = pair_verdict(
            "MIT", "GPL-2.0-only", "Classpath-exception-2.0", LinkType.DYNAMIC
        )
        assert verdict.severity is Severity.CONFLICT
        assert verdict.reason == "weak-copyleft-subllicensing"

    def test_classpath_exception_into_gpl3_warning(self):
        verdict = pair_verdict(
            "GPL-3.0-only", "GPL-2.0-only", "Classpath-exception-2.0", LinkType.DYNAMIC
        )
        # 降级为弱 copyleft；GPL-2.0 不在 GPL-3.0 兼容名单 -> 冲突
        assert verdict.severity is Severity.CONFLICT


class TestStrongCopyleft:
    def test_gpl_component_into_mit_conflict(self):
        verdict = pair_verdict("MIT", "GPL-3.0-only", None, LinkType.DYNAMIC)
        assert verdict.reason == "strong-copyleft-propagation"

    def test_gpl2_only_into_gpl3_conflict(self):
        verdict = pair_verdict("GPL-3.0-only", "GPL-2.0-only", None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.CONFLICT
        assert verdict.reason == "gpl-version-mismatch"

    def test_gpl2_or_later_into_gpl3_compatible(self):
        assert v("GPL-3.0-only", "GPL-2.0-or-later") is None

    def test_gpl3_into_agpl_compatible_one_way(self):
        # FSF：GPLv3 代码可并入 AGPLv3 作品（单向；反向由 AGPL 分支判冲突）
        assert v("AGPL-3.0-only", "GPL-3.0-only") is None
        assert v("AGPL-3.0-only", "GPL-2.0-or-later") is None
        assert v("AGPL-3.0-only", "LGPL-3.0-only") is Severity.WARNING


class TestNetworkCopyleft:
    def test_agpl_into_mit_conflict(self):
        verdict = pair_verdict("MIT", "AGPL-3.0-only", None, LinkType.DYNAMIC)
        assert verdict.reason == "agpl-network-copyleft"
        assert "§13" in verdict.clause

    def test_agpl_into_gpl3_conflict(self):
        verdict = pair_verdict("GPL-3.0-only", "AGPL-3.0-only", None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.CONFLICT

    def test_agpl_same_family_compatible(self):
        assert v("AGPL-3.0-only", "AGPL-3.0-or-later") is None


class TestProprietary:
    def test_openssl_style_into_proprietary(self):
        verdict = pair_verdict(
            "LicenseRef-Proprietary", "GPL-3.0-only", None, LinkType.DYNAMIC
        )
        assert verdict.reason == "copyleft-into-proprietary"

    def test_lgpl_into_proprietary_conflict(self):
        verdict = pair_verdict(
            "LicenseRef-Proprietary", "LGPL-3.0-only", None, LinkType.DYNAMIC
        )
        assert verdict.severity is Severity.CONFLICT

    def test_mit_into_proprietary_compatible(self):
        assert v("LicenseRef-Proprietary", "MIT") is None


class TestUnknown:
    def test_unknown_component_license(self):
        verdict = pair_verdict("MIT", "LicenseRef-Custom-Do-What-You-Want",
                               None, LinkType.DYNAMIC)
        assert verdict.severity is Severity.CONFLICT
        assert verdict.reason == "unknown-license"


class TestExpressions:
    def test_or_component_one_branch_compatible(self):
        result = evaluate_expression(
            parse_expression("MIT"),
            parse_expression("GPL-3.0-only OR MIT"),
            LinkType.DYNAMIC,
        )
        assert result.compatible is True

    def test_and_component_all_must_comply(self):
        result = evaluate_expression(
            parse_expression("MIT"),
            parse_expression("MIT AND GPL-3.0-only"),
            LinkType.DYNAMIC,
        )
        assert result.compatible is False
        assert {l.spdx_id for l in result.conflicts} == {"GPL-3.0-only"}

    def test_project_or_uses_a_compatible_release_option(self):
        # 项目可以 GPL-3.0 或 AGPL-3.0 发布，Apache-2.0 可随 GPL-3.0 发布
        result = evaluate_expression(
            parse_expression("GPL-3.0-only OR AGPL-3.0-only"),
            parse_expression("Apache-2.0"),
            LinkType.DYNAMIC,
        )
        assert result.compatible is True

    def test_agpl_component_forces_project_to_agpl(self):
        result = evaluate_expression(
            parse_expression("GPL-3.0-only OR AGPL-3.0-only"),
            parse_expression("AGPL-3.0-only"),
            LinkType.DYNAMIC,
        )
        assert result.compatible is True  # 项目存在 AGPL 发布选项
        assert result.project_leaf_id == "AGPL-3.0-only"

        result2 = evaluate_expression(
            parse_expression("GPL-3.0-only"),
            parse_expression("AGPL-3.0-only"),
            LinkType.DYNAMIC,
        )
        assert result2.compatible is False
