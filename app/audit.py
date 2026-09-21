"""许可证兼容性审计引擎。

传播模型（简化自 OSI/FSF 与各许可证原文的义务边界）：

* 每个组件声明一个 SPDX 许可证表达式（AND/OR/WITH 均可）。
* 项目“发布许可证”从根节点沿依赖边向下传播：被组合进发布物的
  组件必须能以项目许可证的条款继续分发，否则产生冲突路径。
* 链接方式（静态/动态）只影响弱 copyleft 组件的义务强弱：
  动态链接给出可履行的义务提示(warning)，静态链接提示重新链接义务。
* WITH 例外（如 Classpath-exception-2.0）会把 GPL 组件的
  作品级 copyleft 降级为弱 copyleft。
* OR 表达式按“择一许可”处理：任一分支兼容即兼容；
  AND 表达式按“同时遵守全部许可”处理：所有分支都必须兼容。
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

from .licenses_db import (
    STRONG_COPYLEFT_EXCEPTIONS,
    Copyleft,
    get_license,
)
from .spdx import LicenseNode, NodeKind

ROOT_ID = "__project__"
MAX_PATH_DEPTH = 256  # 防御性：避免环/异常图导致无限递归


class LinkType(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class Severity(str, Enum):
    CONFLICT = "conflict"
    WARNING = "warning"


@dataclass(frozen=True)
class Verdict:
    """一对许可证（项目许可证 id × 组件许可证 id）的判定结果。"""

    severity: Severity | None  # None = 兼容
    reason: str                # 机器可读的原因码
    message: str               # 人类可读描述
    clause: str                # 触发的具体条款（兼容时为空）


@dataclass
class LeafResult:
    """表达式单个许可证叶子的求值结果。"""

    spdx_id: str
    exception: str | None
    verdict: Verdict


@dataclass
class ExpressionResult:
    """整个组件表达式在给定项目许可证叶子下的求值结果。"""

    compatible: bool
    severity: Severity | None
    leaves: list[LeafResult] = field(default_factory=list)
    # 命中的项目发布许可证叶子（OR 项目表达式可能有多个候选）
    project_leaf_id: str | None = None
    # 当表达式不兼容时，AND 分支的“最佳选项”信息（用于替换建议）
    satisfied_leaf_ids: set[str] = field(default_factory=set)

    @property
    def conflicts(self) -> list[LeafResult]:
        return [lf for lf in self.leaves if lf.verdict.severity == Severity.CONFLICT]

    @property
    def warnings(self) -> list[LeafResult]:
        return [lf for lf in self.leaves if lf.verdict.severity == Severity.WARNING]


# ---------------------------------------------------------------- 两两判定

def _matches(project_id: str, compatible_with: frozenset[str]) -> bool:
    """兼容名单匹配；同版本号的 -only 与 -or-later 视为相互满足。"""
    if project_id in compatible_with:
        return True
    variants = {project_id}
    if project_id.endswith("-only"):
        variants.add(project_id[: -len("-only")] + "-or-later")
    elif project_id.endswith("-or-later"):
        variants.add(project_id[: -len("-or-later")] + "-only")
    return bool(variants & compatible_with)


def pair_verdict(project_id: str, component_id: str,
                 component_exception: str | None,
                 link: LinkType) -> Verdict:
    """判定组件许可证能否随 project_id 许可证发布。

    project_id / component_id 均为已规范化的单个 SPDX id（表达式由调用方拆解）。
    """
    project = get_license(project_id)
    component = get_license(component_id)

    # 未识别 id（LicenseRef / 拼写错误）：无法自动判断，按冲突上报
    if component is None:
        return Verdict(
            Severity.CONFLICT, "unknown-license",
            f"组件许可证 {component_id} 不在内置 SPDX 规则库中，无法确认兼容性",
            "Unknown SPDX license identifier",
        )
    if project is None:
        return Verdict(
            Severity.CONFLICT, "unknown-license",
            f"项目许可证 {project_id} 不在内置 SPDX 规则库中，无法确认兼容性",
            "Unknown SPDX license identifier",
        )

    p_cl = project.copyleft
    c_cl = component.copyleft

    # 链接例外把强 copyleft 的传染义务降级为弱 copyleft（如 GPL + Classpath）
    effective_c = c_cl
    if (
        component_exception
        and component_exception in STRONG_COPYLEFT_EXCEPTIONS
        and c_cl in (Copyleft.STRONG, Copyleft.NETWORK)
    ):
        effective_c = Copyleft.WEAK

    # 1) 专有项目不能携带任何开源 copyleft 组件
    if p_cl == Copyleft.PROPRIETARY and c_cl in (
        Copyleft.WEAK, Copyleft.STRONG, Copyleft.NETWORK,
    ):
        return Verdict(
            Severity.CONFLICT, "copyleft-into-proprietary",
            f"{component.name} 是 {c_cl.value} copyleft 许可证，不能并入专有发布许可",
            component.clause,
        )

    # 2) 宽松组件：注意专利条款的特例——Apache-2.0 × GPL-2.0-only 不兼容
    if effective_c == Copyleft.PERMISSIVE:
        if (
            component.patent_clause
            and p_cl == Copyleft.STRONG
            and project_id == "GPL-2.0-only"
            and component_id == "Apache-2.0"
        ):
            return Verdict(
                Severity.CONFLICT, "patent-clause-conflict",
                "Apache-2.0 的专利终止条款与 GPL-2.0-only 冲突（FSF 认定不兼容；"
                "GPL-2.0-or-later 可升级到 GPL-3.0 后兼容）",
                f"{component.clause}; GPL-2.0 §7 (additional terms)",
            )
        return Verdict(None, "compatible", "兼容（宽松许可证）", "")

    # 3) 弱 copyleft 组件进入更强的项目许可证
    if effective_c == Copyleft.WEAK:
        if p_cl in (Copyleft.PERMISSIVE, Copyleft.WEAK):
            # 以更宽松许可证整体发布时，弱 copyleft 文件仍须保留其条款
            return Verdict(
                Severity.CONFLICT, "weak-copyleft-subllicensing",
                f"{component.name} 的弱 copyleft 要求被并入 {project.name} "
                f"({p_cl.value}) 发布时无法继续履行",
                component.clause,
            )
        if p_cl == Copyleft.PROPRIETARY:
            return Verdict(
                Severity.CONFLICT, "copyleft-into-proprietary",
                f"{component.name} 的弱 copyleft 要求与专有发布许可冲突",
                component.clause,
            )
        # 项目本身是强/网络 copyleft：必须在对方的 GPL 兼容名单内
        if p_cl in (Copyleft.STRONG, Copyleft.NETWORK):
            if _matches(project_id, component.gpl_compatible_with):
                if link == LinkType.STATIC:
                    return Verdict(
                        Severity.WARNING, "weak-copyleft-static-link",
                        f"静态链接 {component.name}：须提供目标文件以支持用户"
                        f"用修改版重新链接",
                        component.clause,
                    )
                return Verdict(
                    Severity.WARNING, "weak-copyleft-dynamic-link",
                    f"动态链接 {component.name}：须允许用户替换该库版本并提供其源码",
                    component.clause,
                )
            return Verdict(
                Severity.CONFLICT, "weak-gpl-incompatible",
                f"{component.name} 与 {project.name} 不在相互兼容名单内，"
                f"无法以 {project_id} 条款分发组合作品",
                component.clause,
            )

    # 4) 强 copyleft 组件
    if effective_c == Copyleft.STRONG:
        if p_cl in (Copyleft.PERMISSIVE, Copyleft.WEAK):
            return Verdict(
                Severity.CONFLICT, "strong-copyleft-propagation",
                f"{component.name} 要求整个组合作品以同一许可证发布，"
                f"不能被 {project.name} ({p_cl.value}) 吸纳",
                component.clause,
            )
        if p_cl in (Copyleft.STRONG, Copyleft.NETWORK):
            if _matches(project_id, component.gpl_compatible_with):
                return Verdict(None, "compatible",
                               f"兼容（{component_id} 可升级/并入 {project_id}）", "")
            return Verdict(
                Severity.CONFLICT, "gpl-version-mismatch",
                f"{component.name} 与 {project.name} 版本不兼容："
                f"{component_id} 不允许以 {project_id} 条款分发"
                f"（注意 GPL-2.0-only 不能升级到 GPL-3.0）",
                component.clause,
            )

    # 5) 网络 copyleft 组件（AGPL/SSPL）：项目必须同为 AGPL
    if effective_c == Copyleft.NETWORK:
        if p_cl == Copyleft.NETWORK and _matches(project_id, component.gpl_compatible_with):
            return Verdict(None, "compatible",
                           f"兼容（{component_id} 与 {project_id} 网络 copyleft 一致）", "")
        return Verdict(
            Severity.CONFLICT, "agpl-network-copyleft",
            f"{component.name} 触发网络交互源码提供义务，"
            f"项目必须以 {component.name} 兼容的网络 copyleft 许可证发布（{project.name} 不满足）",
            component.clause,
        )

    # 6) 专有组件（如 Elastic-2.0）随 copyleft 项目分发
    if effective_c == Copyleft.PROPRIETARY and p_cl != Copyleft.PROPRIETARY:
        return Verdict(
            Severity.CONFLICT, "proprietary-component",
            f"{component.name} 的再分发限制与开源项目许可证 {project.name} 冲突",
            component.clause,
        )

    return Verdict(None, "compatible", "兼容", "")


# ---------------------------------------------------------------- 表达式求值

def _eval_node(
    node: LicenseNode,
    project_id: str,
    link: LinkType,
    inherited_exception: str | None = None,
) -> tuple[bool, Severity | None, list[LeafResult]]:
    """递归求值 AST 子树，返回(是否兼容, 最严重等级, 叶子判定列表)。

    兼容的定义是“不存在冲突”；warning（可履行义务，如动态链接 LGPL）
    仍视为兼容，但保留在 severity/叶子列表中用于提示。
    """
    if node.kind == NodeKind.LICENSE:
        exc = inherited_exception
        verdict = pair_verdict(project_id, node.spdx_id or "", exc, link)
        compatible = verdict.severity is not Severity.CONFLICT
        return compatible, verdict.severity, [
            LeafResult(node.spdx_id or "", exc, verdict)
        ]

    if node.kind == NodeKind.WITH:
        child = node.children[0]
        if child.kind != NodeKind.LICENSE:
            # SPDX 规范要求 WITH 仅作用于单个许可证；宽容处理嵌套
            results: list[LeafResult] = []
            ok = True
            worst: Severity | None = None
            for sub in child.leaves():
                v = pair_verdict(project_id, sub.spdx_id or "", node.exception, link)
                results.append(LeafResult(sub.spdx_id or "", node.exception, v))
                if v.severity is Severity.CONFLICT:
                    ok = False
                worst = _worse(worst, v.severity)
            return ok, worst, results
        verdict = pair_verdict(project_id, child.spdx_id or "", node.exception, link)
        compatible = verdict.severity is not Severity.CONFLICT
        return compatible, verdict.severity, [
            LeafResult(child.spdx_id or "", node.exception, verdict)
        ]

    child_outcomes = [
        _eval_node(child, project_id, link, inherited_exception)
        for child in node.children
    ]
    all_leaves = [leaf for _, _, ls in child_outcomes for leaf in ls]
    if node.kind == NodeKind.OR:
        # 择一许可：存在无冲突分支即可（warning 不阻断可选性）
        compatible = any(ok for ok, _, _ in child_outcomes)
        worst = _worse(*(sev for _, sev, _ in child_outcomes))
        return compatible, (worst if compatible else Severity.CONFLICT), all_leaves

    # AND：所有分支都不得有冲突
    compatible = all(ok for ok, _, _ in child_outcomes)
    worst = _worse(*(sev for _, sev, _ in child_outcomes))
    return compatible, (Severity.CONFLICT if not compatible else worst), all_leaves


def _worse(*levels: Severity | None) -> Severity | None:
    if any(s == Severity.CONFLICT for s in levels):
        return Severity.CONFLICT
    if any(s == Severity.WARNING for s in levels):
        return Severity.WARNING
    return None


def _project_leaf_ids(node: LicenseNode) -> list[str]:
    """项目许可证表达式的可发布叶子集合（OR 表示项目可任选其一发布）。"""
    return [n.spdx_id for n in node.leaves() if n.spdx_id]


def evaluate_expression(
    project_expr: LicenseNode,
    component_expr: LicenseNode,
    link: LinkType,
    project_leaf_id: str | None = None,
) -> ExpressionResult:
    """以项目发布许可证求值组件表达式。

    项目表达式含 OR 时，逐个发布选项尝试；只要任一发布选项使组件兼容，
    整体即兼容。project_leaf_id 可固定只评估某一个发布选项（路径传播时使用）。
    """
    leaf_ids = (
        [project_leaf_id] if project_leaf_id else _project_leaf_ids(project_expr)
    )
    best: ExpressionResult | None = None
    for pid in leaf_ids:
        ok, severity, leaves = _eval_node(component_expr, pid, link)
        result = ExpressionResult(
            compatible=ok,
            severity=(severity if ok else Severity.CONFLICT),
            leaves=leaves,
            project_leaf_id=pid,
            satisfied_leaf_ids={lf.spdx_id for lf in leaves
                                if lf.verdict.severity is not Severity.CONFLICT},
        )
        if ok:
            return result
        if best is None:
            best = result
    return best or ExpressionResult(False, Severity.CONFLICT)


def evaluate_all_options(
    project_expr: LicenseNode, component_expr: LicenseNode, link: LinkType
) -> list[ExpressionResult]:
    """项目发布许可证含 OR 时，对每个发布选项分别求值（用于完整冲突报告）。"""
    return [
        evaluate_expression(project_expr, component_expr, link, project_leaf_id=pid)
        for pid in _project_leaf_ids(project_expr)
    ]


# ---------------------------------------------------------------- 路径传播

@dataclass
class ComponentInput:
    key: str
    name: str | None
    version: str | None
    license_expression: str
    replacement_for: str | None = None
    replacement_label: str | None = None
    expr: LicenseNode | None = None


@dataclass
class EdgeInput:
    source: str
    target: str
    link: LinkType = LinkType.DYNAMIC


@dataclass
class PathFinding:
    """一次审计的图与路径传播上下文。"""

    components: dict[str, ComponentInput]
    edges: list[EdgeInput]
    adjacency: dict[str, list[tuple[str, LinkType]]] = field(default_factory=dict)

    @classmethod
    def build(cls, components: list[ComponentInput], edges: list[EdgeInput]) -> "PathFinding":
        index = {c.key: c for c in components}
        adjacency: dict[str, list[tuple[str, LinkType]]] = defaultdict(list)
        for edge in edges:
            adjacency[edge.source].append((edge.target, edge.link))
        return cls(index, edges, dict(adjacency))

    def enumerate_paths(
        self, target: str, max_paths: int
    ) -> list[list[tuple[str, LinkType]]]:
        """枚举根 ROOT_ID -> target 的所有简单路径，按长度升序（BFS）截断。

        返回路径上的节点序列 [(node_id, link_from_parent)]；
        根节点的 link 为 DYNAMIC 占位。每个 BFS 状态携带各自的已访问集合，
        因此不会沿环无限展开。
        """
        found: list[list[tuple[str, LinkType]]] = []
        # 队列元素：(当前节点, 已成形路径, 已访问集合)
        queue: deque[tuple[str, list[tuple[str, LinkType]], frozenset[str]]] = deque()
        queue.append((
            ROOT_ID,
            [(ROOT_ID, LinkType.DYNAMIC)],
            frozenset({ROOT_ID}),
        ))
        while queue and len(found) < max_paths:
            node, path, visited = queue.popleft()
            if len(path) > MAX_PATH_DEPTH:
                continue
            for nxt, link in self.adjacency.get(node, ()):
                if nxt in visited:
                    continue
                new_path = path + [(nxt, link)]
                if nxt == target:
                    if len(found) < max_paths:
                        found.append(new_path)
                else:
                    queue.append((nxt, new_path, visited | {nxt}))
        return found

    def reachable(self) -> set[str]:
        seen = {ROOT_ID}
        queue = deque([ROOT_ID])
        while queue:
            node = queue.popleft()
            for nxt, _ in self.adjacency.get(node, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen
