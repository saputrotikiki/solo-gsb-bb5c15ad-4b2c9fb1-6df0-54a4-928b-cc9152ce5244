"""审计引擎兼容性判定测试。"""
from app.engine import run_audit
from app.models import (
    AuditOptions,
    AuditRequest,
    ComponentIn,
    EdgeIn,
    ProjectIn,
    ComponentReplacement,
)

QUIET = AuditOptions(include_info=True, include_notices=False)


def make(project_license, components, edges, options=None):
    return AuditRequest(
        project=ProjectIn(name="app", release_license=project_license),
        components=[
            ComponentIn(**c) if isinstance(c, dict) else c for c in components
        ],
        graph=[EdgeIn(**e) if isinstance(e, dict) else e for e in edges],
        options=options or QUIET,
    )


def codes(result, severity=None):
    return [
        f["code"] for f in result["findings"]
        if severity is None or f["severity"] == severity
    ]


def test_proprietary_dynamic_lgpl_ok():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "lib", "license": "LGPL-2.1-only"}],
        [{"from": "app", "to": "lib", "linkage": "dynamic"}],
    ))
    assert res["status"] == "compliant"
    assert codes(res, "error") == []


def test_proprietary_static_lgpl_conflict_and_resolution():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{
            "name": "lib", "license": "LGPL-2.1-only",
            "replacements": [ComponentReplacement(name="lib-mit",
                                                  license="MIT")],
        }],
        [{"from": "app", "to": "lib", "linkage": "static"}],
    ))
    assert res["status"] == "conflict"
    f = res["findings"][0]
    assert f["code"] == "STATIC_LINK_WEAK_INTO_PROPRIETARY"
    assert f["path"] == ["app", "lib"]
    assert f["clauses"]  # 触发条款非空
    reso = f["resolution"]
    assert reso["kind"] == "use_dynamic_link"
    assert reso["replacement"]["name"] == "lib-mit"


def test_unknown_linkage_warns():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "lib", "license": "LGPL-2.1-only"}],
        [{"from": "app", "to": "lib", "linkage": "unknown"}],
        AuditOptions(include_info=False, include_notices=False),
    ))
    assert res["status"] == "warnings"
    assert codes(res) == ["UNKNOWN_LINKAGE"]


def test_gpl_into_permissive_upgrades_outbound():
    # MIT/Apache-2.0 等 GPL 兼容宽松许可纳入 GPL 组件时，组合作品整体
    # 以 GPL 发布即合规（出站许可升级），但附带源码提供义务。
    res = run_audit(make(
        "MIT",
        [{
            "name": "gpl", "license": "GPL-3.0-only",
            "replacements": [ComponentReplacement(name="gpl-mit",
                                                  license="MIT")],
        }],
        [{"from": "app", "to": "gpl", "linkage": "dynamic"}],
        AuditOptions(include_info=False, include_notices=True),
    ))
    assert codes(res, "error") == []
    offers = [f for f in res["findings"]
              if f["code"] == "SOURCE_CODE_OFFER"]
    assert offers and offers[0]["path"] == ["app", "gpl"]


def test_gpl_into_proprietary_conflicts_with_replacement():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{
            "name": "gpl", "license": "GPL-3.0-only",
            "replacements": [ComponentReplacement(name="gpl-mit",
                                                  license="MIT")],
        }],
        [{"from": "app", "to": "gpl", "linkage": "dynamic"}],
    ))
    assert res["status"] == "conflict"
    f = res["findings"][0]
    assert f["code"] == "STRONG_COPYLEFT_INTO_PROPRIETARY"
    assert f["resolution"]["replacement"]["name"] == "gpl-mit"


def test_or_dual_license_selectable_branch():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "dual", "license": "GPL-2.0-only OR MIT"}],
        [{"from": "app", "to": "dual", "linkage": "static"}],
    ))
    assert codes(res, "error") == []
    branch = next(f for f in res["findings"]
                  if f["code"] == "OR_BRANCH_SELECTABLE")
    assert branch["resolution"]["kind"] == "choose_branch"
    assert "MIT" in branch["resolution"]["detail"]


def test_or_all_branches_blocked():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "dual", "license": "GPL-2.0-only OR GPL-3.0-only"}],
        [{"from": "app", "to": "dual", "linkage": "static"}],
        AuditOptions(include_info=True, include_notices=False),
    ))
    assert res["status"] == "conflict"
    assert codes(res, "error")  # 至少一条冲突
    assert "OR_BRANCH_ALL_BLOCKED" in codes(res)


def test_apache_gpl2_patent_conflict_symmetric():
    for proj, comp in [
        ("Apache-2.0", "GPL-2.0-only"),
        ("GPL-2.0-only", "Apache-2.0"),
    ]:
        res = run_audit(make(
            proj, [{"name": "x", "license": comp}],
            [{"from": "app", "to": "x", "linkage": "static"}],
        ))
        assert "PATENT_INCOMPATIBILITY" in codes(res), (proj, comp)


def test_apache_gpl3_compatible():
    res = run_audit(make(
        "Apache-2.0", [{"name": "x", "license": "GPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "static"}],
        AuditOptions(include_info=False, include_notices=False),
    ))
    assert codes(res, "error") == []


def test_gpl_or_later_version_unification():
    res = run_audit(make(
        "GPL-2.0-or-later", [{"name": "x", "license": "GPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "static"}],
        AuditOptions(include_info=False, include_notices=False),
    ))
    assert codes(res, "error") == []


def test_gpl_version_mismatch():
    res = run_audit(make(
        "GPL-2.0-only", [{"name": "x", "license": "GPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "static"}],
    ))
    assert "GPL_VERSION_MISMATCH" in codes(res)


def test_gpl_agpl_cross_license_requires_v3():
    bad = run_audit(make(
        "GPL-2.0-only", [{"name": "x", "license": "AGPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "static"}],
    ))
    assert "STRONG_NETWORK_INCOMPATIBLE" in codes(bad)

    good = run_audit(make(
        "GPL-3.0-only", [{"name": "x", "license": "AGPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "static"}],
        AuditOptions(include_info=False, include_notices=False),
    ))
    assert codes(good, "error") == []


def test_lgpl3_into_gpl2_project_conflicts():
    res = run_audit(make(
        "GPL-2.0-only", [{"name": "x", "license": "LGPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "dynamic"}],
    ))
    assert "WEAK_GPL_INCOMPATIBLE" in codes(res)


def test_lgpl3_into_gpl3_project_ok():
    res = run_audit(make(
        "GPL-3.0-only", [{"name": "x", "license": "LGPL-3.0-only"}],
        [{"from": "app", "to": "x", "linkage": "static"}],
        AuditOptions(include_info=False, include_notices=False),
    ))
    assert codes(res, "error") == []


def test_agpl_into_proprietary_conflicts():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "svc", "license": "AGPL-3.0-only"}],
        [{"from": "app", "to": "svc", "linkage": "static"}],
    ))
    assert "NETWORK_COPYLEFT_INTO_PROPRIETARY" in codes(res)


def test_proprietary_into_gpl_conflicts():
    res = run_audit(make(
        "GPL-3.0-only", [{"name": "sdk", "license": "LicenseRef-Proprietary"}],
        [{"from": "app", "to": "sdk", "linkage": "static"}],
    ))
    assert "PROPRIETARY_INTO_COPYLEFT" in codes(res)


def test_classpath_exception_relaxes():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "cp",
          "license": "GPL-2.0-only WITH Classpath-exception-2.0"}],
        [{"from": "app", "to": "cp", "linkage": "static"}],
    ))
    assert codes(res, "error") == []
    assert "LINKING_EXCEPTION_APPLIED" in codes(res)


def test_unknown_exception_does_not_relax():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [{"name": "cp",
          "license": "GPL-2.0-only WITH Weird-Exception"}],
        [{"from": "app", "to": "cp", "linkage": "static"}],
        AuditOptions(include_info=True, include_notices=False),
    ))
    assert codes(res, "error") == ["STRONG_COPYLEFT_INTO_PROPRIETARY"]
    assert "UNKNOWN_EXCEPTION" in codes(res)


def test_conflict_blocks_subtree_duplication():
    res = run_audit(make(
        "LicenseRef-Proprietary",
        [
            {"name": "gpl", "license": "GPL-3.0-only"},
            {"name": "down", "license": "MIT"},
        ],
        [
            {"from": "app", "to": "gpl"},
            {"from": "gpl", "to": "down"},
        ],
        AuditOptions(include_info=False, include_notices=False),
    ))
    errors = [f for f in res["findings"] if f["severity"] == "error"]
    assert len(errors) == 1
    assert errors[0]["path"] == ["app", "gpl"]


def test_cycle_detected_and_truncated():
    res = run_audit(make(
        "MIT",
        [{"name": "a", "license": "MIT"},
         {"name": "b", "license": "MIT"}],
        [{"from": "app", "to": "a"},
         {"from": "a", "to": "b"},
         {"from": "b", "to": "a"}],
    ))
    cyc = next(f for f in res["findings"] if f["code"] == "CYCLE_DETECTED")
    assert cyc["path"] == ["app", "a", "b", "a"]


def test_unreachable_component_reported():
    res = run_audit(make(
        "MIT",
        [{"name": "used", "license": "MIT"},
         {"name": "orphan", "license": "MIT"}],
        [{"from": "app", "to": "used"}],
    ))
    f = next(f for f in res["findings"]
             if f["code"] == "UNREACHABLE_COMPONENT")
    assert f["path"] == ["app", "orphan"]


def test_test_scope_not_propagated():
    res = run_audit(make(
        "MIT",
        [{"name": "gpl-test", "license": "GPL-3.0-only"}],
        [{"from": "app", "to": "gpl-test", "scope": "test"}],
    ))
    assert codes(res, "error") == []


def test_noassertion_warns_and_conservative():
    res = run_audit(make(
        "MIT",
        [{"name": "x", "license": "NOASSERTION"}],
        [{"from": "app", "to": "x"}],
    ))
    assert "UNKNOWN_LICENSE" in codes(res)
    assert res["status"] == "warnings"


def test_scenario_merge_on_project_or():
    res = run_audit(make(
        "GPL-2.0-only OR LicenseRef-Proprietary",
        [{"name": "g3", "license": "GPL-3.0-only"}],
        [{"from": "app", "to": "g3", "linkage": "static"}],
        AuditOptions(include_info=False, include_notices=False),
    ))
    by_scenario = {f["code"]: f.get("scenario")
                   for f in res["findings"] if f["severity"] == "error"}
    assert by_scenario["GPL_VERSION_MISMATCH"] == "GPL-2.0-only"
    assert (by_scenario["STRONG_COPYLEFT_INTO_PROPRIETARY"]
            == "LicenseRef-Proprietary")


def test_path_limit():
    components = [{"name": f"c{i}", "license": "MIT"} for i in range(5)]
    edges = [{"from": "app", "to": "c0"}]
    edges += [{"from": f"c{i}", "to": f"c{i+1}"} for i in range(4)]
    res = run_audit(make(
        "MIT", components, edges,
        AuditOptions(include_info=False, include_notices=False, max_paths=2),
    ))
    assert res["summary"]["max_paths_reached"] is True
    assert "PATH_LIMIT_REACHED" in codes(res)
