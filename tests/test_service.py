"""端到端审计编排（service 层）的语义测试。"""

from app.schemas import AuditRequest
from app.service import run_audit


def _req(project_license, comps, edges=None, **options):
    return AuditRequest(
        project_key="root",
        release_license=project_license,
        components=comps,
        edges=edges or [],
        options={"max_paths_per_component": 10, **options},
    )


def _comp(key, expr, **kw):
    from app.schemas import ComponentIn
    return ComponentIn(key=key, name=key, version="1.0",
                       license_expression=expr, **kw)


def _edge(src, tgt, link="dynamic"):
    from app.schemas import EdgeIn
    return EdgeIn(source=src, target=tgt, link=link)


def _finding_map(resp):
    return {f.component_key: f for f in resp.findings}


class TestORSemantics:
    def test_or_component_compatible_branch_silences_conflict_branch(self):
        req = _req(
            "AGPL-3.0-only",
            [_comp("dual", "GPL-2.0-only OR MIT")],
            [_edge("root", "dual")],
        )
        resp = run_audit(req, max_paths_default=1)
        assert resp.status == "compliant"
        assert resp.findings == []

    def test_or_component_warning_branch_reports_warning_not_conflict(self):
        # GPL-2.0-only 冲突；MPL-2.0 与 AGPL-3.0 可组合但带义务 -> warning
        req = _req(
            "AGPL-3.0-only",
            [_comp("dual", "GPL-2.0-only OR MPL-2.0")],
            [_edge("root", "dual")],
        )
        resp = run_audit(req, max_paths_default=1)
        assert resp.status == "warnings_only"
        f = resp.findings[0]
        assert f.severity == "warning"
        # 冲突分支条款不应出现在 warning 报告里
        assert all("gpl-version-mismatch" != t.reason for t in f.triggering_terms)
        assert f.paths[0].effective_link == "dynamic"

    def test_all_or_branches_conflict(self):
        req = _req(
            "MIT",
            [_comp("bad", "GPL-3.0-only OR AGPL-3.0-only")],
            [_edge("root", "bad")],
        )
        resp = run_audit(req, max_paths_default=1)
        assert resp.status == "conflicts_found"
        assert resp.findings[0].severity == "conflict"


class TestANDSemantics:
    def test_and_all_branches_must_comply(self):
        req = _req(
            "MIT",
            [_comp("mix", "MIT AND GPL-3.0-only")],
            [_edge("root", "mix")],
        )
        resp = run_audit(req, max_paths_default=1)
        f = resp.findings[0]
        assert f.severity == "conflict"
        assert any(t.spdx_id == "GPL-3.0-only" for t in f.triggering_terms)


class TestWithException:
    def test_classpath_exception_in_report(self):
        req = _req(
            "GPL-3.0-only",
            [_comp("cp", "GPL-2.0-only WITH Classpath-exception-2.0")],
            [_edge("root", "cp")],
        )
        resp = run_audit(req, max_paths_default=1)
        terms = resp.findings[0].triggering_terms
        assert terms[0].exception == "Classpath-exception-2.0"


class TestPathPropagation:
    def test_multiple_paths_all_reported(self):
        req = _req(
            "MIT",
            [_comp("a", "MIT"), _comp("b", "MIT"), _comp("g", "GPL-3.0-only")],
            [
                _edge("root", "a"),
                _edge("root", "b"),
                _edge("a", "g", "static"),
                _edge("b", "g", "dynamic"),
            ],
        )
        resp = run_audit(req, max_paths_default=5)
        paths = resp.findings[0].paths
        assert len(paths) == 2
        static_paths = [p for p in paths if p.effective_link == "static"]
        assert len(static_paths) == 1

    def test_path_limit(self):
        comps = [_comp("g", "GPL-3.0-only")]
        edges = []
        for i in range(4):
            comps.append(_comp(f"m{i}", "MIT"))
            edges.append(_edge("root", f"m{i}"))
            edges.append(_edge(f"m{i}", "g"))
        req = AuditRequest(
            project_key="root", release_license="MIT",
            components=comps, edges=edges,
        )
        resp = run_audit(req, max_paths_default=2)
        assert len(resp.findings[0].paths) == 2

    def test_cycle_does_not_hang(self):
        req = _req(
            "MIT",
            [_comp("a", "GPL-3.0-only"), _comp("b", "MIT")],
            [_edge("root", "a"), _edge("a", "b"), _edge("b", "a")],
        )
        resp = run_audit(req, max_paths_default=5)
        assert resp.summary.conflicts == 1

    def test_unreachable_component_audited_by_default(self):
        req = _req(
            "MIT",
            [_comp("used", "MIT"), _comp("orphan", "GPL-3.0-only")],
            [_edge("root", "used")],
        )
        resp = run_audit(req, max_paths_default=1)
        assert resp.summary.unreachable == 1
        assert "orphan" in _finding_map(resp)

    def test_unreachable_skipped_when_disabled(self):
        req = _req(
            "MIT",
            [_comp("used", "MIT"), _comp("orphan", "GPL-3.0-only")],
            [_edge("root", "used")],
            audit_unreachable=False,
        )
        resp = run_audit(req, max_paths_default=1)
        assert "orphan" not in _finding_map(resp)

    def test_warnings_suppressed_by_option(self):
        req = _req(
            "GPL-3.0-only",
            [_comp("l", "LGPL-3.0-only")],
            [_edge("root", "l")],
            include_warnings=False,
        )
        resp = run_audit(req, max_paths_default=1)
        assert resp.status == "compliant"
        assert resp.summary.compatible == 1

    def test_shortest_path_first(self):
        # g 可经 1 跳或 3 跳到达；只取 1 条时必须是最短的
        req = AuditRequest(
            project_key="root", release_license="MIT",
            components=[_comp("g", "GPL-3.0-only"), _comp("a", "MIT"),
                        _comp("b", "MIT")],
            edges=[
                _edge("root", "a"), _edge("a", "b"), _edge("b", "g"),
                _edge("root", "g"),
            ],
            options={"max_paths_per_component": 1},
        )
        resp = run_audit(req, max_paths_default=1)
        path = resp.findings[0].paths[0]
        assert [n.node for n in path.nodes] == ["__project__", "g"]


class TestProjectLicenseOr:
    def test_project_picks_compatible_release_option(self):
        req = _req(
            "MIT OR AGPL-3.0-only",
            [_comp("net", "AGPL-3.0-only")],
            [_edge("root", "net")],
        )
        resp = run_audit(req, max_paths_default=1)
        assert resp.status == "compliant"

    def test_project_license_normalized_in_response(self):
        req = _req("GPL-2.0+", [_comp("x", "MIT")], [_edge("root", "x")])
        resp = run_audit(req, max_paths_default=1)
        assert resp.project.normalized_license == "GPL-2.0-or-later"


class TestReplacements:
    def test_replacement_evaluated(self):
        req = _req(
            "MIT",
            [
                _comp("bad", "GPL-3.0-only"),
                _comp("good", "MIT", replacement_for="bad",
                      replacement_label="fork"),
            ],
            [_edge("root", "bad")],
        )
        resp = run_audit(req, max_paths_default=1)
        repl = resp.findings[0].replacements
        assert len(repl) == 1
        assert repl[0].component_key == "good"
        assert repl[0].compatible is True


def test_fingerprint_stable_and_normalized():
    from app.service import fingerprint_request
    r1 = _req("MIT", [_comp("x", "MIT")], [_edge("root", "x")])
    r2 = _req("MIT", [_comp("x", "MIT")], [_edge("root", "x")])
    assert fingerprint_request(r1) == fingerprint_request(r2)
