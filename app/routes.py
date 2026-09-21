"""HTTP 路由。"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status

from .models import AuditRequest, AuditResponse
from .service import AuditService, get_service

router = APIRouter(tags=["audits"])


@router.post(
    "/audits",
    response_model=AuditResponse,
    status_code=status.HTTP_201_CREATED,
    summary="提交依赖许可兼容性审计（幂等）",
    responses={
        200: {"description": "幂等命中，返回既有审计结果"},
        201: {"description": "新审计已创建"},
    },
)
def create_audit(
    payload: AuditRequest,
    idempotency_key: Optional[str] = Header(
        default=None,
        alias="Idempotency-Key",
        description="可选幂等键；缺省时使用请求体规范化 JSON 的 SHA-256",
    ),
    svc: AuditService = Depends(get_service),
):
    """对组件清单 + 依赖有向图执行许可兼容性审计。

    - 解析项目发布许可与每个组件的 SPDX 表达式（AND/OR/WITH、括号、``+``）。
    - 将项目发布许可沿每条 runtime 依赖路径传播，输出冲突路径、触发条款。
    - 冲突结果中携带可选解决方式：OR 分支选择、动态链接、替换组件、改许可。
    - 相同请求体（或相同 ``Idempotency-Key``）重复提交返回首次审计结果。
    """
    result, created = svc.submit(payload, idempotency_key)
    return result


@router.get(
    "/audits/{audit_id}",
    response_model=AuditResponse,
    summary="按审计 ID 获取审计结果",
)
def get_audit(audit_id: str, svc: AuditService = Depends(get_service)):
    result = svc.get(audit_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "AUDIT_NOT_FOUND",
                    "message": f"审计 {audit_id!r} 不存在或已过期"},
        )
    return {**result, "created": False}


@router.post(
    "/audits/evaluate",
    response_model=AuditResponse,
    summary="只做一次性评估（不落幂等仓库）",
)
def evaluate(payload: AuditRequest, svc: AuditService = Depends(get_service)):
    """执行审计逻辑但不写入幂等仓库，适合 CI 中无状态调用。"""
    result, _ = svc.submit(payload, persist=False)
    return result
