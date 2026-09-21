"""API 层：幂等、错误信封、OpenAPI、健康检查。"""
from fastapi.testclient import TestClient

from app.main import app
from app.service import AuditService
import app.service as service_module

client = TestClient(app)

SAMPLE = {
    "project": {"name": "app", "release_license": "LicenseRef-Proprietary"},
    "components": [
        {"name": "gpl", "version": "3.0", "license": "GPL-3.0-only",
         "replacements": [
             {"name": "gpl-mit", "license": "MIT",
              "url": "https://example.com", "note": "精简重写版"}
         ]},
        {"name": "json", "version": "1", "license": "MIT"},
    ],
    "graph": [
        {"from": "app", "to": "gpl", "linkage": "dynamic"},
        {"from": "app", "to": "json", "linkage": "static"},
    ],
    "options": {"include_info": False, "include_notices": False},
}


def setup_function(_):
    service_module.service_singleton = AuditService()


def test_health_and_root():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/").json()["api"] == "/api/v1/audits"


def test_openapi_documented():
    spec = client.get("/openapi.json").json()
    assert spec["info"]["title"]
    assert "/api/v1/audits" in spec["paths"]
    post = spec["paths"]["/api/v1/audits"]["post"]
    assert "Idempotency-Key" in str(post["parameters"])
    assert "AuditRequest" in spec["components"]["schemas"]


def test_create_audit_conflict():
    r = client.post("/api/v1/audits", json=SAMPLE)
    assert r.status_code == 201
    d = r.json()
    assert d["created"] is True
    assert d["status"] == "conflict"
    assert d["audit_id"] and d["idempotency_key"]
    finding = d["findings"][0]
    assert finding["path"] == ["app", "gpl"]
    assert finding["clauses"]
    assert finding["resolution"]["replacement"]["name"] == "gpl-mit"


def test_idempotent_same_body():
    first = client.post("/api/v1/audits", json=SAMPLE).json()
    second = client.post("/api/v1/audits", json=SAMPLE).json()
    assert first["audit_id"] == second["audit_id"]
    assert second["created"] is False


def test_idempotent_key_header():
    r1 = client.post("/api/v1/audits", json=SAMPLE,
                     headers={"Idempotency-Key": "run-001"})
    # 不同体但同键（这里体相同），命中缓存。
    r2 = client.post("/api/v1/audits", json=SAMPLE,
                     headers={"Idempotency-Key": "run-001"})
    assert r1.json()["audit_id"] == r2.json()["audit_id"]
    assert r2.json()["created"] is False


def test_different_body_different_audit():
    a = client.post("/api/v1/audits", json=SAMPLE).json()
    other = {**SAMPLE,
             "project": {"name": "app", "release_license": "Apache-2.0"}}
    b = client.post("/api/v1/audits", json=other).json()
    assert a["audit_id"] != b["audit_id"]


def test_get_audit():
    created = client.post("/api/v1/audits", json=SAMPLE).json()
    got = client.get(f"/api/v1/audits/{created['audit_id']}")
    assert got.status_code == 200
    assert got.json()["audit_id"] == created["audit_id"]


def test_get_audit_404():
    r = client.get("/api/v1/audits/nope")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "AUDIT_NOT_FOUND"


def test_evaluate_not_persisted():
    r = client.post("/api/v1/audits/evaluate", json=SAMPLE)
    assert r.status_code == 200
    aid = r.json()["audit_id"]
    assert client.get(f"/api/v1/audits/{aid}").status_code == 404


def test_invalid_spdx_returns_422_envelope():
    bad = {**SAMPLE,
           "project": {"name": "app", "release_license": "MIT AND"}}
    r = client.post("/api/v1/audits", json=bad)
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["code"] == "INVALID_GRAPH"
    assert body["error"]["pointer"] == "project.release_license"


def test_invalid_graph_returns_422():
    bad = {
        **SAMPLE,
        "graph": [{"from": "app", "to": "ghost"}],
    }
    r = client.post("/api/v1/audits", json=bad)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INVALID_GRAPH"


def test_validation_error_envelope():
    r = client.post("/api/v1/audits", json={"project": {"name": "x"}})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
