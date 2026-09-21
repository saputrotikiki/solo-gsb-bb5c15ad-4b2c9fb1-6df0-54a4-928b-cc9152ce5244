"""审计编排：把 HTTP 模型、SPDX 解析、规则引擎与路径传播串起来。"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .audit import (
    ROOT_ID,
    ComponentInput,
    EdgeInput,
    LinkType,
    PathFinding,
    evaluate_all_options,
)
from .licenses_db import get_license
from .schemas import (
    AuditRequest,
    AuditResponse,
    AuditSummary,
    ConflictPath,
    FindingOut,
    PathNode,
    ProjectInfo,
    ReplacementSuggestion,
    TriggeringTerm,
)
from .spdx import ExpressionError, NodeKind, parse_expression


class AuditInputError(ValueError):
    """清单/图本身有问题（区别于发现许可证冲突）。"""


def _expression_to_text(node) -> str:
    """把 AST 还原成规范化的表达式文本（用于响应展示）。"""
    if node.kind == NodeKind.LICENSE:
        return node.spdx_id or ""
    if node.kind == NodeKind.WITH:
        return f"{_expression_to_text(node.children[0])} WITH {node.exception}"
    op = " AND " if node.kind == NodeKind.AND else " OR "
    return "(" + op.join(_expression_to_text(c) for c in node.children) + ")"


def fingerprint_request(request: AuditRequest) -> str:
    """对审计输入做规范化哈希，作为天然 audit_id（内容相同 -> 结果相同）。"""
    payload = request.model_dump()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _worst_result(results) -> object | None:
    """多个发布选项中选出最有代表性的结果：优先无冲突，否则取第一个。"""
    for r in results:
        if r.compatible:
            return r
    return results[0] if results else None


def run_audit(req: AuditRequest, *, max_paths_default: int) -> AuditResponse:
    # ---- 1. 解析项目发布许可证表达式 ----
    try:
        project_expr = parse_expression(req.release_license)
    except ExpressionError as exc:
        raise AuditInputError(f"项目许可证表达式无效: {exc}") from exc

    # ---- 2. 解析全部组件表达式 ----
    components: dict[str, ComponentInput] = {}
    parse_warnings: dict[str, list[str]] = {}
    for comp in req.components:
        if comp.key in components:
            raise AuditInputError(f"组件 key 重复: {comp.key}")
        try:
            comp.expr = parse_expression(comp.license_expression)
        except ExpressionError as exc:
            raise AuditInputError(
                f"组件 {comp.key} 的许可证表达式无效: {exc}"
            ) from exc
        warnings: list[str] = []
        for leaf in comp.expr.leaves():
            if leaf.unknown and get_license(leaf.spdx_id or "") is None:
                warnings.append(f"未识别的许可证标识 {leaf.spdx_id}")
        components[comp.key] = comp
        parse_warnings[comp.key] = warnings

    # ---- 3. 建图并校验边 ----
    edges: list[EdgeInput] = []
    root_aliases = {ROOT_ID, req.project_key, "root", "project"}
    for edge in req.edges:
        source = ROOT_ID if edge.source in root_aliases else edge.source
        target = ROOT_ID if edge.target in root_aliases else edge.target
        if source != ROOT_ID and source not in components:
            raise AuditInputError(
                f"边 {edge.source} -> {edge.target} 的起点不在组件清单中"
            )
        if target not in components:
            raise AuditInputError(
                f"边 {edge.source} -> {edge.target} 的终点不在组件清单中"
            )
        edges.append(EdgeInput(source, target, LinkType(edge.link.value)))

    graph = PathFinding.build(list(components.values()), edges)
    reachable = graph.reachable() - {ROOT_ID}
    max_paths = req.options.max_paths_per_component or max_paths_default

    # 替换节点索引：replacement_for -> [组件]
    replacements_index: dict[str, list[ComponentInput]] = {}
    for comp in components.values():
        if comp.replacement_for:
            replacements_index.setdefault(comp.replacement_for, []).append(comp)

    findings: list[FindingOut] = []
    n_conflict = n_warning = n_compatible = 0

    # ---- 4. 逐组件：沿依赖路径传播项目发布许可证 ----
    for key in sorted(components):
        raw = components[key]
        paths = graph.enumerate_paths(key, max_paths)
        if key not in reachable and not req.options.audit_unreachable:
            continue

        # 先做一次基线评估（dynamic），判断组件是否可以兼容
        base_results = evaluate_all_options(project_expr, raw.expr, LinkType.DYNAMIC)

        conflict_paths: list[ConflictPath] = []
        warning_paths: list[ConflictPath] = []
        clean_options: set[str] = set()       # 完全无冲突也无义务提示的发布选项
        warn_only_options: set[str] = set()   # 兼容但带义务提示的发布选项

        def _classify(result) -> str:
            if not result.compatible:
                return "conflict"
            return "warning" if result.warnings else "clean"

        if paths:
            for path in paths:
                # 路径上的链接方式：任一静态链接即按静态处理（义务最严格）
                effective_link = LinkType.DYNAMIC
                if any(link == LinkType.STATIC for _, link in path):
                    effective_link = LinkType.STATIC

                per_option = evaluate_all_options(
                    project_expr, raw.expr, effective_link
                )
                nodes = [
                    PathNode(node=nid, link=(None if i == 0 else lnk))
                    for i, (nid, lnk) in enumerate(path)
                ]
                for result in per_option:
                    leaf_id = result.project_leaf_id or ""
                    status = _classify(result)
                    if status == "clean":
                        clean_options.add(leaf_id)
                        continue
                    cp = ConflictPath(
                        nodes=nodes,
                        project_license_leaf=leaf_id,
                        effective_link=effective_link,
                    )
                    if status == "conflict":
                        conflict_paths.append(cp)
                    else:
                        warning_paths.append(cp)
                        warn_only_options.add(leaf_id)
        else:
            # 孤立组件（不在任何依赖路径上）：直接基于基线评估定级
            for result in base_results:
                status = _classify(result)
                if status == "clean":
                    clean_options.add(result.project_leaf_id or "")
                elif status == "warning":
                    warn_only_options.add(result.project_leaf_id or "")

        # 任一项目发布选项可使组件完全兼容 -> 不报告
        if clean_options:
            n_compatible += 1
            continue
        # 关闭义务提示时，warning-only 组件视为通过
        if warn_only_options and not req.options.include_warnings:
            n_compatible += 1
            continue

        # ---- 5. 汇总触发条款（跨路径/跨发布选项去重）----
        term_leafs: dict[tuple[str, str, str | None], object] = {}
        for result in base_results:
            for leaf in result.conflicts + result.warnings:
                sig = (leaf.spdx_id, leaf.verdict.reason, leaf.exception)
                term_leafs.setdefault(sig, leaf)
        for warning in parse_warnings.get(key, []):
            unknown_id = warning.split()[-1]
            term_leafs.setdefault(
                (unknown_id, "unknown-license", None),
                _UnknownLeaf(unknown_id),
            )

        # 所有发布选项均冲突 -> conflict；至少一个选项可带义务兼容 -> warning
        has_conflict = not clean_options and not warn_only_options
        emitted_paths = conflict_paths if has_conflict else warning_paths

        # 触发条款只保留与最终等级一致的叶子（OR 择一后无关分支不再报告）
        wanted_severity = "conflict" if has_conflict else "warning"
        triggering: list[TriggeringTerm] = []
        for (spdx_id, reason, exception), leaf in term_leafs.items():
            leaf_level = getattr(leaf.verdict, "severity", None)
            leaf_level = getattr(leaf_level, "value", leaf_level)
            if leaf_level and leaf_level != wanted_severity:
                continue
            info = get_license(spdx_id)
            triggering.append(TriggeringTerm(
                spdx_id=spdx_id,
                license_name=info.name if info else spdx_id,
                exception=exception,
                reason=reason,
                message=getattr(leaf.verdict, "message",
                                f"未识别的许可证标识 {spdx_id}"),
                clause=getattr(leaf.verdict, "clause",
                               "Unknown SPDX license identifier"),
            ))

        # ---- 6. 可选替换节点评估 ----
        replacements: list[ReplacementSuggestion] = []
        for cand in replacements_index.get(key, []):
            cand_results = evaluate_all_options(project_expr, cand.expr, LinkType.DYNAMIC)
            cand_ok = any(r.compatible for r in cand_results)
            replacements.append(ReplacementSuggestion(
                component_key=cand.key, name=cand.name, version=cand.version,
                license_expression=cand.license_expression,
                label=cand.replacement_label,
                compatible=cand_ok,
                note="该替换节点与项目发布许可证兼容"
                if cand_ok else "该替换节点仍不兼容，仅列出供参考",
            ))

        if has_conflict:
            severity = "conflict"
            n_conflict += 1
        else:
            severity = "warning"
            n_warning += 1

        findings.append(FindingOut(
            id=f"F-{key}",
            severity=severity,
            component_key=key,
            component_name=raw.name,
            component_version=raw.version,
            license_expression=raw.license_expression,
            paths=emitted_paths,
            triggering_terms=triggering,
            replacements=replacements,
        ))

    unreachable = len(set(components) - reachable)
    audited = len(findings) + n_compatible
    status = "compliant"
    if n_conflict:
        status = "conflicts_found"
    elif n_warning:
        status = "warnings_only"

    audit_id = fingerprint_request(req)
    return AuditResponse(
        audit_id=audit_id,
        status=status,
        project=ProjectInfo(
            key=req.project_key, name=req.project_name,
            release_license=req.release_license,
            normalized_license=_expression_to_text(project_expr),
        ),
        findings=findings,
        summary=AuditSummary(
            total_components=len(components),
            audited_components=audited,
            conflicts=n_conflict,
            warnings=n_warning,
            compatible=n_compatible,
            unreachable=unreachable,
        ),
    )


class _UnknownLeaf:
    """解析期发现的未知许可证，构造触发条款时的轻量占位。"""

    class _Verdict:
        reason = "unknown-license"
        message = "未识别的许可证标识"
        clause = "Unknown SPDX license identifier"

    verdict = _Verdict()

    def __init__(self, spdx_id: str) -> None:
        self.spdx_id = spdx_id
        self.exception = None


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
