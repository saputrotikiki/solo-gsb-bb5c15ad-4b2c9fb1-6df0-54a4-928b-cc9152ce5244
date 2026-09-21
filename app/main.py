"""FastAPI 入口：审计接口、幂等键、OpenAPI 文档。"""

from __future__ import annotations

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from . import __version__
from .config import settings
from .schemas import (
    AuditListItem,
    AuditRequest,
    AuditResponse,
    ErrorResponse,
    LicenseEntry,
)
from .service import AuditInputError, fingerprint_request, run_audit, utcnow_iso
from .store import IdempotentStore, KeyInUse
from .licenses_db import LICENSES

app = FastAPI(
    title="依赖许可兼容性审计 API",
    description=(
        "接收组件清单、依赖有向图与 SPDX 许可证表达式（支持 AND / OR / WITH 组合），"
        "将项目发布许可证沿依赖路径传播，返回每条冲突路径、触发条款及可选替换节点。\n\n"
        "幂等性：相同请求内容产生相同 `audit_id`（请求体 SHA-256），"
        "也可通过 `Idempotency-Key` 请求头绑定自定义键。"
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

store = IdempotentStore()


def _error(code: str, message: str, status: int = 400,
           detail: str | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content=ErrorResponse(error=message, code=code, detail=detail).model_dump(),
    )


@app.exception_handler(AuditInputError)
async def _audit_input_handler(_request: Request, exc: AuditInputError) -> JSONResponse:
    return _error("invalid_audit_input", str(exc), status=422)


@app.exception_handler(KeyInUse)
async def _key_in_use_handler(_request: Request, exc: KeyInUse) -> JSONResponse:
    return _error(
        "idempotency_key_conflict",
        f"Idempotency-Key {exc.key!r} 已绑定另一份审计请求",
        status=409,
    )


@app.get("/health", tags=["系统"], summary="健康检查")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post(
    "/api/v1/audits",
    response_model=AuditResponse,
    status_code=200,
    tags=["审计"],
    summary="提交组件清单执行许可证兼容性审计（幂等）",
    responses={
        409: {"model": ErrorResponse, "description": "Idempotency-Key 冲突"},
        422: {"model": ErrorResponse, "description": "请求/表达式/依赖图不合法"},
    },
)
async def create_audit(
    body: AuditRequest,
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
        description="客户端幂等键；同键重放首次结果，同键不同载荷返回 409",
    ),
) -> AuditResponse:
    fingerprint = fingerprint_request(body)
    # 自定义幂等键优先：同键不同载荷直接冲突
    if idempotency_key:
        keyed = store.get_by_key(idempotency_key)
        if keyed:
            if keyed.fingerprint != fingerprint:
                raise KeyInUse(idempotency_key)
            keyed.response.replayed = True
            keyed.response.idempotency_key = idempotency_key
            return keyed.response
    # 内容指纹幂等：相同请求天然得到相同结果
    existing = store.get_by_id(fingerprint)
    if existing:
        existing.response.replayed = True
        existing.response.idempotency_key = idempotency_key or existing.idempotency_key
        return existing.response

    response = run_audit(body, max_paths_default=settings.default_max_paths)
    response.idempotency_key = idempotency_key
    record, _ = store.put(idempotency_key, fingerprint, response, utcnow_iso())
    record.response.replayed = False
    return record.response


@app.get(
    "/api/v1/audits/{audit_id}",
    response_model=AuditResponse,
    tags=["审计"],
    summary="按 audit_id 获取历史审计结果",
    responses={404: {"model": ErrorResponse, "description": "审计不存在"}},
)
async def get_audit(audit_id: str) -> AuditResponse:
    record = store.get_by_id(audit_id)
    if not record:
        return _error("audit_not_found", f"审计 {audit_id} 不存在", status=404)  # type: ignore[return-value]
    record.response.replayed = True
    return record.response


@app.get(
    "/api/v1/audits",
    response_model=list[AuditListItem],
    tags=["审计"],
    summary="列出已执行的审计（按时间倒序）",
)
async def list_audits() -> list[AuditListItem]:
    return [
        AuditListItem(
            audit_id=r.response.audit_id,
            idempotency_key=r.idempotency_key,
            created_at=r.created_at,
            status=r.response.status,
            component_count=r.response.summary.total_components,
        )
        for r in store.list_all()
    ]


@app.get(
    "/api/v1/licenses",
    response_model=list[LicenseEntry],
    tags=["规则"],
    summary="列出内置许可证规则（copyleft 等级与触发条款）",
)
async def list_licenses() -> list[LicenseEntry]:
    return [
        LicenseEntry(
            spdx_id=lic.spdx_id, name=lic.name,
            copyleft=lic.copyleft.value, clause=lic.clause,
        )
        for lic in sorted(LICENSES.values(), key=lambda x: x.spdx_id)
    ]


def main() -> None:  # 供 `python -m app.main` 本地启动
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=settings.app_env == "development",
    )


if __name__ == "__main__":
    main()
