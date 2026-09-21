"""FastAPI 应用入口。"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .engine import GraphValidationError
from .routes import router

settings = get_settings()

TAGS_METADATA = [
    {
        "name": "audits",
        "description": "依赖许可兼容性审计：SPDX 表达式解析、沿依赖路径传播"
        "发布许可、冲突路径/触发条款/替换建议。",
    },
]

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    openapi_tags=TAGS_METADATA,
    description=(
        "## 依赖许可兼容性审计 API\n\n"
        "- 接收 **组件清单**、**依赖有向图** 与项目 **SPDX 许可证表达式**\n"
        "- 解析 `AND` / `OR` / `WITH`、括号与 `+` 后缀（归一化为 "
        "`-only`/`-or-later`）\n"
        "- 将项目发布许可沿每条 runtime 依赖路径传播，返回冲突路径、"
        "触发条款（章节 + SPDX URL）与可选替换节点\n"
        "- `POST /api/v1/audits` 幂等：相同请求体或相同 `Idempotency-Key` "
        "返回首次结果\n\n"
        "> 审计结果是工程辅助信息，不构成法律意见。"
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_allow_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _error(code: str, message: str, status_code: int,
           pointer: str | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message,
                           "pointer": pointer}},
    )


@app.exception_handler(GraphValidationError)
async def graph_validation_handler(_request: Request,
                                   exc: GraphValidationError) -> JSONResponse:
    return _error("INVALID_GRAPH", str(exc), 422, exc.pointer)


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request,
                                 exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        return _error(detail["code"], detail.get("message", ""),
                      exc.status_code, detail.get("pointer"))
    return _error("HTTP_ERROR", str(detail), exc.status_code)


@app.exception_handler(RequestValidationError)
async def request_validation_handler(_request: Request,
                                     exc: RequestValidationError) -> JSONResponse:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"] if p != "body")
        parts.append(f"{loc or '<root>'}: {err['msg']}")
    return _error("VALIDATION_ERROR", "; ".join(parts), 422)


@app.exception_handler(Exception)
async def unhandled_handler(_request: Request, exc: Exception) -> JSONResponse:
    return _error("INTERNAL_ERROR", f"内部错误：{exc}", 500)


@app.get("/health", tags=["audits"], summary="健康检查")
async def health() -> dict:
    return {"status": "ok", "version": settings.version}


@app.get("/", tags=["audits"], summary="服务信息")
async def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
        "openapi": "/openapi.json",
        "api": "/api/v1/audits",
    }


app.include_router(router, prefix="/api/v1")
