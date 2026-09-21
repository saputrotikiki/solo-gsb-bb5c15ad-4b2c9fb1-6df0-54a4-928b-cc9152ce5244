"""HTTP 层 Pydantic 模型（OpenAPI 文档即由这些模型生成）。"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class LinkType(str, Enum):
    static = "static"
    dynamic = "dynamic"


# ---------------------------------------------------------------- 请求

class ComponentIn(BaseModel):
    key: str = Field(..., min_length=1, description="组件在依赖图中的唯一标识，如包名或 purl")
    name: str | None = Field(None, description="组件显示名")
    version: str | None = Field(None, description="组件版本")
    license_expression: str = Field(
        ..., min_length=1,
        description="SPDX 许可证表达式，如 'Apache-2.0 OR MIT'、"
                    "'GPL-2.0-only WITH Classpath-exception-2.0'",
    )
    # 替换节点声明：该组件可作为哪个冲突组件的替代
    replacement_for: str | None = Field(
        None, description="若该组件是可选替换节点，填写被替换组件的 key"
    )
    replacement_label: str | None = Field(
        None, description="替换说明，如 'MIT 分叉版本 2.1'"
    )

    # 服务端解析后的表达式 AST，不参与请求序列化/指纹
    model_config = ConfigDict(arbitrary_types_allowed=True)
    expr: object | None = Field(default=None, exclude=True, repr=False)


class EdgeIn(BaseModel):
    source: str = Field(..., description="依赖方节点 key；根依赖使用项目 key 或 'root'")
    target: str = Field(..., description="被依赖组件 key")
    link: LinkType = Field(LinkType.dynamic, description="链接/集成方式")


class AuditOptions(BaseModel):
    max_paths_per_component: int | None = Field(
        None, ge=1, le=100,
        description="每个冲突组件最多返回多少条依赖路径（默认取最短冲突路径）",
    )
    include_warnings: bool = Field(
        True, description="是否返回可履行义务类提示（弱 copyleft 链接等）"
    )
    audit_unreachable: bool = Field(
        True, description="是否审计未出现在依赖图路径上的孤立组件"
    )


class AuditRequest(BaseModel):
    project_key: str = Field("root", description="项目根节点 key（图中以它为起点）")
    project_name: str | None = Field(None, description="项目名称")
    release_license: str = Field(
        ..., min_length=1,
        description="项目发布许可证 SPDX 表达式，将沿依赖路径向下传播",
    )
    components: list[ComponentIn] = Field(..., min_length=1)
    edges: list[EdgeIn] = Field(default_factory=list)
    options: AuditOptions = Field(default_factory=AuditOptions)


# ---------------------------------------------------------------- 响应

class PathNode(BaseModel):
    node: str
    link: LinkType | None = None


class ConflictPath(BaseModel):
    nodes: list[PathNode] = Field(..., description="从项目根到冲突组件的完整路径")
    project_license_leaf: str = Field(..., description="该路径上传播的项目发布许可证叶子")
    effective_link: LinkType = Field(..., description="路径上最严格的链接方式（任一 static 即 static）")


class TriggeringTerm(BaseModel):
    spdx_id: str
    license_name: str
    exception: str | None = None
    reason: str
    message: str
    clause: str = Field(..., description="触发冲突/义务的具体许可证条款")


class ReplacementSuggestion(BaseModel):
    component_key: str
    name: str | None = None
    version: str | None = None
    license_expression: str
    label: str | None = None
    compatible: bool
    note: str


class FindingOut(BaseModel):
    id: str
    severity: str
    component_key: str
    component_name: str | None = None
    component_version: str | None = None
    license_expression: str
    paths: list[ConflictPath]
    triggering_terms: list[TriggeringTerm]
    replacements: list[ReplacementSuggestion] = Field(default_factory=list)


class ProjectInfo(BaseModel):
    key: str
    name: str | None = None
    release_license: str
    normalized_license: str = Field(..., description="规范化后的许可证表达式文本")


class AuditSummary(BaseModel):
    total_components: int
    audited_components: int
    conflicts: int
    warnings: int
    compatible: int
    unreachable: int


class AuditResponse(BaseModel):
    audit_id: str
    idempotency_key: str | None = None
    replayed: bool = Field(False, description="true 表示命中幂等缓存，结果为历史快照")
    status: str = Field(..., description="compliant | conflicts_found | warnings_only")
    project: ProjectInfo
    findings: list[FindingOut]
    summary: AuditSummary


class AuditListItem(BaseModel):
    audit_id: str
    idempotency_key: str | None = None
    created_at: str
    status: str
    component_count: int


class LicenseEntry(BaseModel):
    spdx_id: str
    name: str
    copyleft: str
    clause: str


class ErrorResponse(BaseModel):
    error: str
    code: str
    detail: str | None = None
