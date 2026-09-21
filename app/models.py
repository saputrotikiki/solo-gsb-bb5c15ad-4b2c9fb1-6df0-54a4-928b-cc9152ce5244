"""Pydantic 请求/响应模型。"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

LinkageType = Literal["static", "dynamic", "unknown"]


class ComponentReplacement(BaseModel):
    """可选替换组件建议。"""

    name: str = Field(..., description="替换组件名称", examples=["libsodium-mit"])
    license: str = Field(..., description="替换组件的 SPDX 许可证表达式", examples=["MIT"])
    url: Optional[str] = Field(None, description="替换组件主页或仓库地址")
    note: Optional[str] = Field(None, description="替换说明（成本/差异等）")


class ComponentIn(BaseModel):
    name: str = Field(..., min_length=1, examples=["glibc"])
    version: Optional[str] = Field(None, examples=["2.39"])
    license: str = Field(
        ...,
        min_length=1,
        description="SPDX 许可证表达式，支持 AND / OR / WITH、括号与 + 后缀",
        examples=["LGPL-2.1-or-later"],
    )
    replacements: list[ComponentReplacement] = Field(
        default_factory=list, description="可选替换节点"
    )


class EdgeIn(BaseModel):
    """依赖有向图中的一条边：from 依赖 to。"""

    from_node: str = Field(..., alias="from", description="依赖方（项目或组件名）")
    to_node: str = Field(..., alias="to", description="被依赖组件")
    linkage: LinkageType = Field(
        "unknown", description="链接方式，弱著佐权许可传播时需要（static/dynamic）"
    )
    scope: Literal["runtime", "build", "test"] = Field(
        "runtime", description="依赖作用域；test 作用域不参与发布许可传播"
    )

    model_config = {"populate_by_name": True}


class ProjectIn(BaseModel):
    name: str = Field(..., min_length=1, examples=["shop-backend"])
    version: Optional[str] = Field(None, examples=["1.2.0"])
    release_license: str = Field(
        ...,
        min_length=1,
        description="项目发布许可 SPDX 表达式，将沿依赖路径传播",
        examples=["GPL-2.0-only"],
    )


class AuditOptions(BaseModel):
    include_info: bool = Field(True, description="是否返回 info 级别结果（如例外生效提示）")
    include_notices: bool = Field(
        True, description="是否返回归属声明/源码提供等 notice 级义务"
    )
    max_paths: int = Field(
        2000, ge=1, le=10000, description="单次审计最多枚举的依赖路径数"
    )


class AuditRequest(BaseModel):
    project: ProjectIn
    components: list[ComponentIn] = Field(default_factory=list)
    graph: list[EdgeIn] = Field(default_factory=list)
    options: AuditOptions = Field(default_factory=AuditOptions)


class ClauseRef(BaseModel):
    license_id: str = Field(..., description="许可证/例外 SPDX 标识")
    section: str = Field(..., description="触发的条款名称或章节号")
    url: str = Field(..., description="条款查阅地址")


class ReplacementResolution(BaseModel):
    kind: Literal[
        "choose_branch",
        "use_dynamic_link",
        "add_exception",
        "replace_component",
        "relicense",
    ]
    detail: str
    component: Optional[str] = None
    replacement: Optional[ComponentReplacement] = None


class Finding(BaseModel):
    severity: Literal["error", "warning", "info"]
    code: str = Field(..., description="问题代码，如 STATIC_LINK_STRONG_INTO_PROPRIETARY")
    message: str
    path: list[str] = Field(..., description="触发该问题的依赖路径（项目为起点）")
    edge: Optional[tuple[str, str]] = Field(
        None, description="触发该问题的依赖边 [from, to]"
    )
    clauses: list[ClauseRef] = Field(default_factory=list, description="触发条款")
    scenario: Optional[str] = Field(
        None, description="项目发布许可的具体分支（DNF 场景）"
    )
    resolution: Optional[ReplacementResolution] = Field(
        None, description="可选替换/解决方式"
    )


class AuditSummary(BaseModel):
    paths_scanned: int
    max_paths_reached: bool
    errors: int
    warnings: int
    infos: int
    components: int
    edges: int
    scenarios: list[str]
    status: Literal["compliant", "warnings", "conflict"]


class AuditResponse(BaseModel):
    audit_id: str
    idempotency_key: str
    project: ProjectIn
    created: bool = Field(..., description="true=本次新建审计；false=幂等命中缓存")
    created_at: str
    status: Literal["compliant", "warnings", "conflict"]
    summary: AuditSummary
    findings: list[Finding]
    request: AuditRequest


class ErrorDetail(BaseModel):
    code: str
    message: str
    pointer: Optional[str] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
