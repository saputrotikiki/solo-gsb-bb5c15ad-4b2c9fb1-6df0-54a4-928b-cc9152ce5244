import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    # 每个测试使用全新的内存幂等存储，避免 audit_id/key 跨用例干扰
    from app.store import IdempotentStore
    app.dependency_overrides = {}
    client = TestClient(app)
    import app.main as main_module
    main_module.store = IdempotentStore()
    return client


def _base_request():
    return {
        "project_key": "root",
        "project_name": "demo",
        "release_license": "AGPL-3.0-or-later",
        "components": [
            {"key": "web", "name": "web", "version": "1.0",
             "license_expression": "MIT"},
            {"key": "gpl2lib", "name": "gpl2lib", "version": "0.9",
             "license_expression": "GPL-2.0-only"},
            {"key": "gpl2lib-fork", "name": "gpl2lib fork", "version": "1.0",
             "license_expression": "MIT",
             "replacement_for": "gpl2lib",
             "replacement_label": "MIT 分叉"},
            {"key": "lgpl3", "name": "lgpl3 lib", "version": "2.0",
             "license_expression": "LGPL-3.0-only"},
            {"key": "dual", "name": "dual licensed", "version": "1.0",
             "license_expression": "MIT OR GPL-2.0-only"},
        ],
        "edges": [
            {"source": "root", "target": "web", "link": "static"},
            {"source": "web", "target": "gpl2lib", "link": "static"},
            {"source": "root", "target": "gpl2lib", "link": "dynamic"},
            {"source": "root", "target": "lgpl3", "link": "dynamic"},
            {"source": "root", "target": "dual", "link": "dynamic"},
        ],
        "options": {"max_paths_per_component": 10},
    }


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_openapi_docs_available(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_audit_conflicts_paths_and_replacements(client):
    resp = client.post("/api/v1/audits", json=_base_request())
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "conflicts_found"
    assert data["replayed"] is False

    by_key = {f["component_key"]: f for f in data["findings"]}

    # GPL-2.0-only 组件进入 AGPL-3.0 项目：冲突
    conflict = by_key["gpl2lib"]
    assert conflict["severity"] == "conflict"
    # 存在两条依赖路径：root->web->gpl2lib 与 root->gpl2lib
    paths = conflict["paths"]
    assert len(paths) == 2
    lengths = sorted(len(p["nodes"]) for p in paths)
    assert lengths == [2, 3]
    # 静态链接路径被识别
    static_path = next(p for p in paths if len(p["nodes"]) == 3)
    assert static_path["effective_link"] == "static"
    assert static_path["project_license_leaf"] == "AGPL-3.0-or-later"
    # 触发条款指向 GPL-2.0 §2(b)
    assert any("GPL-2.0" in t["clause"] for t in conflict["triggering_terms"])

    # 替换节点建议
    repl = conflict["replacements"]
    assert len(repl) == 1
    assert repl[0]["component_key"] == "gpl2lib-fork"
    assert repl[0]["compatible"] is True

    # LGPL-3.0 动态链接 AGPL 项目：warning（允许，需履行义务）
    warning = by_key["lgpl3"]
    assert warning["severity"] == "warning"
    assert warning["paths"][0]["effective_link"] == "dynamic"
    assert any("LGPL-3.0" in t["clause"] for t in warning["triggering_terms"])

    # 双重许可组件：MIT 分支兼容 -> 整体兼容，不出现在 findings
    assert "dual" not in by_key


def test_idempotent_same_payload_same_audit_id(client):
    payload = _base_request()
    r1 = client.post("/api/v1/audits", json=payload)
    r2 = client.post("/api/v1/audits", json=payload)
    assert r1.json()["audit_id"] == r2.json()["audit_id"]
    assert r2.json()["replayed"] is True

    # GET 历史结果
    audit_id = r1.json()["audit_id"]
    r3 = client.get(f"/api/v1/audits/{audit_id}")
    assert r3.status_code == 200
    assert r3.json()["audit_id"] == audit_id
    assert r3.json()["replayed"] is True


def test_idempotency_key_header_replay(client):
    payload = _base_request()
    r1 = client.post("/api/v1/audits", json=payload,
                     headers={"Idempotency-Key": "run-001"})
    assert r1.status_code == 200
    r2 = client.post("/api/v1/audits", json=payload,
                     headers={"Idempotency-Key": "run-001"})
    assert r2.json()["audit_id"] == r1.json()["audit_id"]
    assert r2.json()["replayed"] is True


def test_idempotency_key_conflict(client):
    p1 = _base_request()
    p2 = _base_request()
    p2["release_license"] = "MIT"
    client.post("/api/v1/audits", json=p1, headers={"Idempotency-Key": "k"})
    resp = client.post("/api/v1/audits", json=p2, headers={"Idempotency-Key": "k"})
    assert resp.status_code == 409
    assert resp.json()["code"] == "idempotency_key_conflict"


def test_list_audits(client):
    client.post("/api/v1/audits", json=_base_request())
    resp = client.get("/api/v1/audits")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_get_missing_audit_404(client):
    resp = client.get("/api/v1/audits/nope")
    assert resp.status_code == 404
    assert resp.json()["code"] == "audit_not_found"


def test_invalid_expression_returns_422(client):
    payload = _base_request()
    payload["release_license"] = "GPL-2.0 AND"
    resp = client.post("/api/v1/audits", json=payload)
    assert resp.status_code == 422
    assert resp.json()["code"] == "invalid_audit_input"


def test_edge_references_missing_component_422(client):
    payload = _base_request()
    payload["edges"].append({"source": "root", "target": "ghost", "link": "dynamic"})
    resp = client.post("/api/v1/audits", json=payload)
    assert resp.status_code == 422
    assert "终点" in resp.json()["error"]


def test_unknown_license_flagged(client):
    payload = {
        "project_key": "root",
        "release_license": "MIT",
        "components": [
            {"key": "weird", "license_expression":
             "LicenseRef-Company-Internal-1.0"}
        ],
        "edges": [{"source": "root", "target": "weird", "link": "dynamic"}],
    }
    resp = client.post("/api/v1/audits", json=payload)
    assert resp.status_code == 200
    finding = resp.json()["findings"][0]
    assert finding["severity"] == "conflict"
    assert finding["triggering_terms"][0]["reason"] == "unknown-license"


def test_with_exception_downgrades_copyleft(client):
    # GPL-2.0-only + Classpath 进入 GPL-3.0 项目：
    # 例外降级为弱 copyleft，但 LGPL-2.1-only 与 GPL-3 不兼容 -> 仍冲突，
    # 原因码变为 weak-gpl-incompatible
    payload = {
        "project_key": "root",
        "release_license": "GPL-3.0-only",
        "components": [
            {"key": "cp", "license_expression":
             "GPL-2.0-only WITH Classpath-exception-2.0"}
        ],
        "edges": [{"source": "root", "target": "cp", "link": "dynamic"}],
    }
    resp = client.post("/api/v1/audits", json=payload)
    terms = resp.json()["findings"][0]["triggering_terms"]
    reasons = {t["reason"] for t in terms}
    assert "weak-gpl-incompatible" in reasons
    assert any(t["exception"] == "Classpath-exception-2.0" for t in terms)


def test_licenses_catalog(client):
    resp = client.get("/api/v1/licenses")
    ids = {entry["spdx_id"] for entry in resp.json()}
    assert {"MIT", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-3.0-only"} <= ids
