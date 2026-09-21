"""许可证兼容性审计引擎。

工作流程：

1. 校验组件清单与依赖有向图（见 :class:`GraphValidationError`）。
2. 解析项目发布许可 SPDX 表达式并展开为 DNF 场景（OR 分支 × AND 组合），
   每个 AND 组取约束最强的许可作为沿路径传播的初始“出站许可”。
3. 对每个场景自项目根沿依赖边做深度优先遍历；在每个节点解析组件许可证
   表达式（AND/OR/WITH），将父节点传播下来的出站许可与该节点许可做兼容性
   判定，得到问题（error/warning/info）与新的出站许可继续向子节点传播。
4. 合并各场景下路径相同的问题，给出触发条款与可选替换节点。

说明（刻意保持的简化，README“审计规则与边界”一节有同样描述）：

- 链接方式只对 *弱著佐权* 许可（LGPL/MPL/EPL/CDDL）有意义：动态链接构成
  许可边界，静态链接不构成；GPL/AGPL 不因动态链接而豁免分发义务。
- 传播模型为“项目发布许可自上而下传播”，不做反向传染推断；环在路径上
  截断并告警。
- 结果是工程辅助信息，不构成法律意见。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .catalog import (
    EXCEPTIONS,
    classify,
    exception_clause,
    get_license,
    license_clause,
    linking_relaxed,
    parse_versioned,
)
from .models import AuditRequest, ComponentIn
from .spdx import License as Leaf
from .spdx import And, Node, Or, dnf_groups, parse_spdx

MAX_DEPTH = 64

# 类别强度（用于 AND 组合与出站许可选择）
_STRENGTH = {
    "neutral": -1,
    "public": 0,
    "permissive": 1,
    "none": 1,
    "unknown": 1,
    "noassertion": 1,
    "weak_copyleft": 2,
    "strong_copyleft": 3,
    "network": 4,
}


class GraphValidationError(ValueError):
    """清单/图/SPDX 表达式校验失败，映射为 HTTP 422。"""

    def __init__(self, message: str, pointer: Optional[str] = None):
        super().__init__(message)
        self.pointer = pointer


@dataclass(frozen=True)
class LState:
    """沿依赖路径传播的出站许可状态。"""

    category: str
    lid: str
    exception: Optional[str] = None
    version: Optional[object] = None  # catalog.VersionedLicense
    gpl_versions: tuple[int, ...] = ()
    agpl_versions: tuple[int, ...] = ()
    gpl_family: bool = False
    relaxed: bool = False

    @property
    def is_copyleft(self) -> bool:
        return self.category in ("strong_copyleft", "network")

    @property
    def is_weak(self) -> bool:
        return self.category == "weak_copyleft"


# 项目根的中性起点：不施加任何许可约束，故项目自身声明 GPL/LGPL/专有
# 均不会产生“与上游冲突”。
NEUTRAL = LState(category="neutral", lid="NEUTRAL")


@dataclass
class Draft:
    """尚未绑定路径的审计问题草稿。"""

    severity: str
    code: str
    message: str
    clauses: list[dict] = field(default_factory=list)
    resolution: Optional[dict] = None
    flavor: str = "issue"  # issue / info / notice


@dataclass
class ExprEval:
    issues: list[Draft]
    state: Optional[LState]
    branch_label: str
    blocked: bool = False


# ---------------------------------------------------------------------------
# 状态构造
# ---------------------------------------------------------------------------

def state_of(leaf: Leaf) -> LState:
    lid = leaf.spdx_id
    cat = classify(lid)
    info = get_license(lid)
    gplv: tuple[int, ...] = ()
    agplv: tuple[int, ...] = ()
    gpl_family = False
    if info is not None and info.category == "weak_copyleft":
        gplv = info.gpl_versions or ()
        agplv = info.agpl_versions or ()
        gpl_family = info.gpl_family
    return LState(
        category=cat,
        lid=lid,
        exception=leaf.exception,
        version=parse_versioned(lid),
        gpl_versions=gplv,
        agpl_versions=agplv,
        gpl_family=gpl_family,
        relaxed=linking_relaxed(leaf.exception),
    )


def _perm_state(lid: str = "MIT") -> LState:
    return state_of(Leaf(lid))


def _clauses_for(lid: str, *kinds: str) -> list[dict]:
    info = get_license(lid)
    out: list[dict] = []
    if info is None:
        return [license_clause(lid)]
    if "main" in kinds:
        out.append(license_clause(lid, info.section))
    if "source" in kinds and info.source_section:
        out.append(license_clause(lid, info.source_section))
    if "network" in kinds and info.network_section:
        out.append(license_clause(lid, info.network_section))
    if "notice" in kinds and info.notice_section:
        out.append(license_clause(lid, info.notice_section))
    if "patent" in kinds and info.patent_section:
        out.append(license_clause(lid, info.patent_section))
    return [c for c in out if c["section"]]


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------

def validate_request(req: AuditRequest) -> dict[str, ComponentIn]:
    project = req.project.name
    names: set[str] = set()
    comps: dict[str, ComponentIn] = {}
    try:
        parse_spdx(req.project.release_license)
    except Exception as exc:  # noqa: BLE001
        raise GraphValidationError(str(exc), "project.release_license") from exc

    for idx, c in enumerate(req.components):
        if c.name == project:
            raise GraphValidationError(
                f"组件名 {c.name!r} 不能与项目同名", f"components[{idx}].name"
            )
        if c.name in names:
            raise GraphValidationError(
                f"组件名重复：{c.name!r}", f"components[{idx}].name"
            )
        names.add(c.name)
        try:
            parse_spdx(c.license)
        except Exception as exc:  # noqa: BLE001
            raise GraphValidationError(
                str(exc), f"components[{idx}].license"
            ) from exc
        for r_idx, repl in enumerate(c.replacements):
            try:
                parse_spdx(repl.license)
            except Exception as exc:  # noqa: BLE001
                raise GraphValidationError(
                    str(exc),
                    f"components[{idx}].replacements[{r_idx}].license",
                ) from exc
        comps[c.name] = c

    seen_edges: set[tuple[str, str]] = set()
    for idx, e in enumerate(req.graph):
        if e.from_node == e.to_node:
            raise GraphValidationError(
                f"自环边不允许：{e.from_node!r}", f"graph[{idx}]"
            )
        if e.from_node != project and e.from_node not in names:
            raise GraphValidationError(
                f"边起点 {e.from_node!r} 既不是项目也不是已知组件",
                f"graph[{idx}].from",
            )
        if e.to_node not in names:
            raise GraphValidationError(
                f"边终点 {e.to_node!r} 不是已知组件", f"graph[{idx}].to"
            )
        if e.to_node == project:
            raise GraphValidationError(
                "依赖边不能指向项目节点", f"graph[{idx}].to"
            )
        key = (e.from_node, e.to_node)
        if key in seen_edges:
            raise GraphValidationError(
                f"重复的依赖边：{e.from_node!r} -> {e.to_node!r}",
                f"graph[{idx}]",
            )
        seen_edges.add(key)
    return comps


# ---------------------------------------------------------------------------
# 替换节点评估
# ---------------------------------------------------------------------------

def _compatible_replacements(
    comp: ComponentIn, in_state: LState, linkage: str
) -> list[dict]:
    out: list[dict] = []
    for repl in comp.replacements:
        try:
            ast = parse_spdx(repl.license)
        except Exception:  # noqa: BLE001
            continue
        groups = dnf_groups(ast)
        # 替换件存在无 error 的 OR 分支即视为可行；唯一可接受的条件性 error
        # 是 Apache-2.0/GPL-2.0-only 专利冲突（可随 GPL 升级解决）。
        feasible = False
        conditional = ""
        chosen = ""
        for group in groups:
            state = in_state
            ok = True
            for leaf in group:
                ev = _assess_leaf(leaf, state, linkage, comp.name, None)
                if ev.state is not None:
                    state = ev.state
                errors = [i for i in ev.issues if i.severity == "error"]
                hard = [i for i in errors
                        if i.code != "PATENT_INCOMPATIBILITY"]
                if hard:
                    ok = False
                    break
                if errors and not conditional:
                    conditional = "需同时将 GPL-2.0-only 升级为 GPL-3.0"
            if ok:
                feasible = True
                chosen = " AND ".join(l.label for l in group)
                break
        if feasible:
            out.append(
                {
                    "name": repl.name,
                    "license": repl.license,
                    "url": repl.url,
                    "note": repl.note,
                    "feasible_branch": chosen,
                    "conditional": conditional,
                }
            )
    return out


def _res_replace(comp: ComponentIn, in_state: LState, linkage: str) -> Optional[dict]:
    repls = _compatible_replacements(comp, in_state, linkage)
    if not repls:
        return None
    r = repls[0]
    detail = f"可替换为 {r['name']}（{r['license']}"
    if r["feasible_branch"]:
        detail += f"，可行分支 {r['feasible_branch']}"
    detail += "），与当前传播路径上的发布许可兼容"
    if r.get("conditional"):
        detail += f"（条件：{r['conditional']}）"
    return {
        "kind": "replace_component",
        "detail": detail,
        "component": comp.name,
        "replacement": {
            "name": r["name"],
            "license": r["license"],
            "url": r["url"],
            "note": r["note"],
        },
    }


def _attach_all_replacements(draft: Draft, comp: ComponentIn,
                             in_state: LState, linkage: str) -> None:
    repl = _res_replace(comp, in_state, linkage)
    if not repl:
        return
    if draft.resolution is None:
        draft.resolution = repl
        return
    # 已有非替换类建议（动态链接/改许可）时，保留其类型并把替换节点
    # 结构化附加，文字描述并入 detail。
    draft.resolution["detail"] += "；" + repl["detail"]
    if not draft.resolution.get("replacement"):
        draft.resolution["replacement"] = repl["replacement"]


# ---------------------------------------------------------------------------
# 强/网络著佐权版本组合
# ---------------------------------------------------------------------------

def _gpl_combine(parent: LState, child: LState):
    """返回 (combined_state|None, error_code|None, error_message|None)。"""
    pv = parent.version
    cv = child.version
    if pv is None or cv is None:
        return child, None, None
    if pv.family == cv.family:
        if pv.version == cv.version:
            if _STRENGTH[child.category] >= _STRENGTH[parent.category]:
                return child, None, None
            return parent, None, None
        # 任一方 -or-later 可升级到更高版本。
        can_up_parent = parent.lid.endswith("-or-later") and pv.version <= cv.version
        can_up_child = child.lid.endswith("-or-later") and cv.version <= pv.version
        if can_up_parent or can_up_child:
            winner = child if cv.version >= pv.version else parent
            return winner, None, None
        return (
            None,
            "GPL_VERSION_MISMATCH",
            f"{parent.lid} 与 {child.lid} 版本互不兼容：双方均非 -or-later，"
            "无法统一到同一 GPL 版本",
        )
    # GPL <-> AGPL：仅在可统一到 v3 时依 AGPL-3.0 第13条交叉许可。
    p3 = pv.version == 3 or (parent.lid.endswith("-or-later") and pv.version <= 3)
    c3 = cv.version == 3 or (child.lid.endswith("-or-later") and cv.version <= 3)
    if p3 and c3:
        agpl = child if child.category == "network" else parent
        return agpl, None, None
    return (
        None,
        "STRONG_NETWORK_INCOMPATIBLE",
        f"{parent.lid} 与 {child.lid} 冲突：AGPL-3.0 仅允许与 GPL-3.0"
        "（或可升级至 GPL-3.0 的 -or-later）组合为统一的 AGPL 作品",
    )


def _weak_version_combine(parent: LState, child: LState):
    """同族弱著佐权（LGPL/LGPL）静态组合。"""
    pv, cv = parent.version, child.version
    if pv is None or cv is None:
        return child, None, None
    if pv.version == cv.version:
        return child, None, None
    if (parent.lid.endswith("-or-later") and pv.version <= cv.version) or (
        child.lid.endswith("-or-later") and cv.version <= pv.version
    ):
        return child if cv.version >= pv.version else parent, None, None
    return (
        None,
        "LGPL_VERSION_MISMATCH",
        f"静态组合的 {parent.lid} 与 {child.lid} 版本不一致且均不能升级，"
        "无法满足同一 LGPL 版本条款",
    )


def _weak_accepts(weak: LState, family: str, version: int) -> bool:
    """弱著佐权能否接受指定 GPL/AGPL 版本的强著佐权并入。"""
    if family == "AGPL":
        return version in weak.agpl_versions
    return version in weak.gpl_versions


# ---------------------------------------------------------------------------
# 单子句许可证（叶子）判定
# ---------------------------------------------------------------------------

def _assess_leaf(leaf: Leaf, parent: LState, linkage: str,
                 comp_name: str, comp: Optional[ComponentIn]) -> ExprEval:
    lid = leaf.spdx_id
    exception = leaf.exception
    child = state_of(leaf)
    cat = child.category
    pcat = parent.category
    issues: list[Draft] = []
    state_out: Optional[LState] = child

    def attach(d: Draft) -> Draft:
        if comp is not None:
            _attach_all_replacements(d, comp, parent, linkage)
        return d

    # 未知/缺失许可 ---------------------------------------------------------
    if cat == "none":
        issues.append(attach(Draft(
            "warning", "UNLICENSED_COMPONENT",
            f"组件 {comp_name} 声明为 SPDX NONE（不授予任何许可），"
            "不具备再分发权利",
            [license_clause("NONE")],
        )))
        # 项目根为 NONE 时按最保守的“专有”约束传播；依赖节点处不改变出站许可。
        if pcat == "neutral":
            return ExprEval(issues, state_of(Leaf("LicenseRef-Proprietary")),
                            leaf.label)
        return ExprEval(issues, parent, leaf.label)
    if cat == "noassertion":
        issues.append(attach(Draft(
            "warning", "UNKNOWN_LICENSE",
            f"组件 {comp_name} 的许可证为 NOASSERTION，无法判定兼容性，"
            "需人工核实许可条款",
            [license_clause("NOASSERTION")],
        )))
        if pcat == "neutral":
            return ExprEval(issues, state_of(Leaf("LicenseRef-Proprietary")),
                            leaf.label)
        return ExprEval(issues, parent, leaf.label)
    if cat == "unknown":
        issues.append(attach(Draft(
            "warning", "UNKNOWN_LICENSE",
            f"组件 {comp_name} 使用目录外标识 {lid}，无法自动判定兼容性，"
            "需人工核实",
            [license_clause(lid)],
        )))
        if pcat == "neutral":
            return ExprEval(issues, state_of(Leaf("LicenseRef-Proprietary")),
                            leaf.label)
        return ExprEval(issues, parent, leaf.label)

    # 例外识别 ---------------------------------------------------------------
    if exception is not None and exception not in EXCEPTIONS:
        issues.append(Draft(
            "info", "UNKNOWN_EXCEPTION",
            f"组件 {comp_name} 使用了目录外例外 {exception}，"
            "不假设其放宽任何条款，需人工核实",
            [exception_clause(exception)],
            flavor="info",
        ))

    # Apache-2.0 与 GPL-2.0-only 专利条款冲突（对称） -------------------------
    apache_gpl2 = {
        ("GPL-2.0-only", "Apache-2.0"),
        ("Apache-2.0", "GPL-2.0-only"),
    }
    if (parent.lid, lid) in apache_gpl2:
        d = Draft(
            "error", "PATENT_INCOMPATIBILITY",
            "Apache-2.0 第3条专利授权与 GPL-2.0-only 第7条专利 retaliation "
            "条款相互冲突，无法在同一组合作品中同时满足",
            _clauses_for("Apache-2.0", "main", "patent")
            + _clauses_for("GPL-2.0-only", "main"),
        )
        d.resolution = {
            "kind": "relicense",
            "detail": "将 GPL-2.0-only 一方升级为 GPL-3.0（或 -or-later），"
                      "GPL-3.0 第7条与 Apache-2.0 专利条款兼容",
        }
        issues.append(attach(d))
        return ExprEval(issues, child, leaf.label)

    # 宽松许可 / 公共领域 ------------------------------------------------------
    if cat in ("permissive", "public"):
        info = get_license(lid)
        if info and info.notice_section:
            issues.append(Draft(
                "info", "NOTICE_ATTRIBUTION",
                f"组件 {comp_name}（{lid}）要求保留版权/许可声明，"
                "请在再分发文档中加注归属声明",
                _clauses_for(lid, "notice"),
                flavor="notice",
            ))
        if pcat in ("strong_copyleft", "network", "proprietary", "weak_copyleft",
                    "none", "unknown", "noassertion"):
            state_out = parent
        elif pcat in ("public", "neutral"):
            state_out = child if cat == "permissive" else parent
        elif pcat == "permissive":
            # 宽松 + 公共领域：约束较强的宽松许可继续传播。
            state_out = parent if cat == "public" else child
        else:
            state_out = parent
        return ExprEval(issues, state_out, leaf.label)

    # 专有子节点 --------------------------------------------------------------
    if cat == "proprietary":
        if pcat in ("strong_copyleft", "network"):
            fam = "AGPL" if pcat == "network" else "GPL"
            d = Draft(
                "error", "PROPRIETARY_INTO_COPYLEFT",
                f"专有组件 {comp_name} 不能与 {fam} 发布许可组合："
                f"{fam} 要求组合作品整体以同等条款发布，专有许可无法满足",
                _clauses_for(parent.lid, "main"),
            )
            d.resolution = {
                "kind": "relicense",
                "detail": f"以 {fam} 兼容的自由许可替换该专有组件，"
                          f"或将项目发布许可改为非著佐权许可",
                "component": comp_name,
            }
            issues.append(attach(d))
            return ExprEval(issues, parent, leaf.label)
        # 宽松/弱著佐权（动态边界）/公共领域下，专有许可成为出站约束。
        return ExprEval(issues, child, leaf.label)

    # 弱著佐权 ----------------------------------------------------------------
    if cat == "weak_copyleft":
        # 链接例外放宽：不产生著佐权传染，但保留归属提示。
        if child.relaxed:
            issues.append(Draft(
                "info", "LINKING_EXCEPTION_APPLIED",
                f"组件 {comp_name} 带 {exception} 链接例外，"
                "允许与独立模块（含专有代码）链接而不触发弱著佐权条款",
                [exception_clause(exception)],  # type: ignore[arg-type]
                flavor="info",
            ))
            if _STRENGTH[pcat] >= _STRENGTH["weak_copyleft"]:
                state_out = parent
            else:
                state_out = child
            return ExprEval(issues, state_out, leaf.label)

        info = get_license(lid)
        if info and info.source_section:
            issues.append(Draft(
                "info", "SOURCE_CODE_OFFER",
                f"组件 {comp_name}（{lid}）为弱著佐权：修改部分需以可重新链接"
                "的方式提供目标文件/源代码",
                _clauses_for(lid, "source"),
                flavor="notice",
            ))

        # 父为强/网络著佐权：弱著佐权可按版本矩阵转换并入，整体仍受父约束。
        if pcat in ("strong_copyleft", "network"):
            family = parent.version.family if parent.version else "GPL"
            pver = parent.version.version if parent.version else None
            ok_family = child.gpl_family or family in ("GPL", "AGPL")
            compatible = ok_family and (
                pver is None
                or (family == "AGPL" and pver in child.agpl_versions)
                or (family != "AGPL" and pver in child.gpl_versions)
            )
            if not compatible:
                d = Draft(
                    "error", "WEAK_GPL_INCOMPATIBLE",
                    f"{lid} 不能并入 {parent.lid} 作品：其 GPL 兼容版本"
                    f"（{sorted(child.gpl_versions)}）不包含父许可要求的 "
                    f"{family}-{pver}",
                    _clauses_for(lid, "main") + _clauses_for(parent.lid, "main"),
                )
                issues.append(attach(d))
            return ExprEval(issues, parent, leaf.label)

        # 父为弱著佐权。
        if pcat == "weak_copyleft":
            if linkage == "dynamic":
                # 动态链接构成许可边界：该节点按自身弱著佐权许可继续传播。
                return ExprEval(issues, child, leaf.label)
            if linkage == "unknown":
                d = Draft(
                    "warning", "UNKNOWN_LINKAGE",
                    f"组件 {comp_name}（{lid}）与同为弱著佐权的上游之间链接方式"
                    "未知：动态链接构成许可边界，静态链接则需满足版本一致",
                    _clauses_for(lid, "main"),
                )
                d.resolution = {
                    "kind": "use_dynamic_link",
                    "detail": "将该依赖改为动态链接，使弱著佐权许可边界成立",
                    "component": comp_name,
                }
                issues.append(d)
                return ExprEval(issues, parent, leaf.label)
            # static
            if child.gpl_family and parent.gpl_family:
                combined, code, msg = _weak_version_combine(parent, child)
                if code:
                    issues.append(attach(Draft(
                        "error", code, msg,
                        _clauses_for(parent.lid, "main")
                        + _clauses_for(lid, "main"),
                    )))
                    return ExprEval(issues, parent, leaf.label)
                return ExprEval(issues, combined or child, leaf.label)
            issues.append(attach(Draft(
                "error", "WEAK_FAMILY_INCOMPATIBLE",
                f"静态组合两个不同家族的弱著佐权许可 {parent.lid} 与 {lid}："
                "文件级著佐权条件无法在同一静态二进制中同时满足，"
                "请改为动态链接或替换其一",
                _clauses_for(parent.lid, "main") + _clauses_for(lid, "main"),
            )))
            return ExprEval(issues, child, leaf.label)

        # 父为专有/宽松/公共领域。
        if pcat == "proprietary" and linkage == "static":
            d = Draft(
                "error", "STATIC_LINK_WEAK_INTO_PROPRIETARY",
                f"专有/闭源发布物静态链接 {lid} 组件 {comp_name}，"
                "触发弱著佐权：必须提供允许用户替换该库的目标文件与源代码",
                _clauses_for(lid, "main", "source"),
            )
            d.resolution = {
                "kind": "use_dynamic_link",
                "detail": "改为动态链接（共享库）即可在不开放专有代码的情况下"
                          "满足 LGPL 的重新链接要求",
                "component": comp_name,
            }
            issues.append(attach(d))
            return ExprEval(issues, child, leaf.label)
        if pcat == "proprietary" and linkage == "unknown":
            d = Draft(
                "warning", "UNKNOWN_LINKAGE",
                f"专有发布物对 {lid} 组件 {comp_name} 的链接方式未知，"
                "若为静态链接将构成冲突",
                _clauses_for(lid, "main"),
            )
            d.resolution = {
                "kind": "use_dynamic_link",
                "detail": "确认并声明为动态链接，或提供可重新链接材料",
                "component": comp_name,
            }
            issues.append(d)
        # 子树继续按该弱著佐权许可传播。
        return ExprEval(issues, child, leaf.label)

    # 强著佐权 / 网络著佐权 ---------------------------------------------------
    assert cat in ("strong_copyleft", "network")
    is_network = cat == "network"
    exc_info = EXCEPTIONS.get(exception) if exception else None
    if exc_info and exc_info.effect == "output_exempt":
        issues.append(Draft(
            "info", "OUTPUT_EXCEPTION_APPLIED",
            f"组件 {comp_name} 带 {exception}：其编译器/工具产生的输出不"
            "受著佐权条款约束",
            [exception_clause(exception)],  # type: ignore[arg-type]
            flavor="info",
        ))
        return ExprEval(issues, parent, leaf.label)
    if child.relaxed:
        issues.append(Draft(
            "info", "LINKING_EXCEPTION_APPLIED",
            f"组件 {comp_name} 带 {exception} 链接例外，链接例外范围内"
            "不触发著佐权传染；例外范围之外的修改仍受原许可约束",
            [exception_clause(exception)],  # type: ignore[arg-type]
            flavor="info",
        ))
        if pcat not in ("strong_copyleft", "network", "weak_copyleft"):
            return ExprEval(issues, child, leaf.label)
        # 父仍为著佐权时继续走版本组合。

    if is_network:
        issues.append(Draft(
            "info", "NETWORK_SOURCE_OFFER",
            f"组件 {comp_name}（AGPL-3.0）通过网络与用户交互即触发源码提供："
            "必须向所有远程用户提供对应完整源代码",
            _clauses_for(lid, "network", "source"),
            flavor="notice",
        ))
    else:
        issues.append(Draft(
            "info", "SOURCE_CODE_OFFER",
            f"组件 {comp_name}（{lid}）要求分发组合作品时提供对应源代码",
            _clauses_for(lid, "source"),
            flavor="notice",
        ))

    if pcat in ("strong_copyleft", "network"):
        combined, code, msg = _gpl_combine(parent, child)
        if code:
            issues.append(attach(Draft(
                "error", code, msg,
                _clauses_for(parent.lid, "main") + _clauses_for(lid, "main"),
            )))
            return ExprEval(issues, parent, leaf.label)
        return ExprEval(issues, combined or child, leaf.label)

    if pcat == "weak_copyleft":
        family = child.version.family if child.version else "GPL"
        cver = child.version.version if child.version else None
        if cver is not None and not _weak_accepts(parent, family, cver):
            allowed = (parent.agpl_versions if family == "AGPL"
                       else parent.gpl_versions)
            issues.append(attach(Draft(
                "error", "WEAK_GPL_INCOMPATIBLE",
                f"{parent.lid} 不能与 {lid} 组合：其可转换的 {family} 版本"
                f"{sorted(allowed)} 不包含 {family}-{cver}",
                _clauses_for(parent.lid, "main") + _clauses_for(lid, "main"),
            )))
            return ExprEval(issues, parent, leaf.label)
        # 弱著佐权允许按兼容版本转换为 GPL/AGPL，出站许可升级为子许可。
        return ExprEval(issues, child, leaf.label)

    # 父为专有/宽松/公共领域（项目根的中性起点除外，根只是声明自身许可）。
    if pcat not in ("neutral",):
        # GPL 兼容的宽松许可可整体转换为 GPL/AGPL 出站（单向兼容），
        # MIT/BSD/Apache-2.0 对 GPL-3、CC0 等均属此类；
        # Apache-2.0 与 GPL-2.0-only 的专利冲突已在前面单独拦截。
        permissive_ok = pcat in ("permissive", "public")
        if not permissive_ok and is_network:
            d = Draft(
                "error", "NETWORK_COPYLEFT_INTO_PROPRIETARY",
                f"{lid} 组件 {comp_name} 与 {pcat} 发布许可冲突：AGPL 要求网络"
                "交互的组合作品整体以 AGPL 开放源代码，专有发布无法满足",
                _clauses_for(lid, "main", "network"),
            )
            d.resolution = {
                "kind": "relicense",
                "detail": "将整体发布许可改为 AGPL-3.0，或替换该组件为"
                          "非网络著佐权许可的等价实现",
                "component": comp_name,
            }
            issues.append(attach(d))
            return ExprEval(issues, child, leaf.label)
        if not permissive_ok:
            d = Draft(
                "error", "STRONG_COPYLEFT_INTO_PROPRIETARY",
                f"{lid} 组件 {comp_name} 与 {pcat} 发布许可冲突：GPL 要求组合"
                "作品整体以同等条款发布；动态链接不构成 GPL 下的许可边界",
                _clauses_for(lid, "main"),
            )
            d.resolution = {
                "kind": "relicense",
                "detail": "将项目发布许可改为 GPL 兼容许可，或替换该组件"
                          "（如 MIT/Apache-2.0/LGPL 动态链接版本）",
                "component": comp_name,
            }
            issues.append(attach(d))
    return ExprEval(issues, child, leaf.label)


# ---------------------------------------------------------------------------
# 表达式求值（AND / OR）
# ---------------------------------------------------------------------------

def _eval_expr(node: Node, parent: LState, linkage: str,
               comp_name: str, comp: Optional[ComponentIn]) -> ExprEval:
    if isinstance(node, Leaf):
        return _assess_leaf(node, parent, linkage, comp_name, comp)

    if isinstance(node, Or):
        left = _eval_expr(node.left, parent, linkage, comp_name, comp)
        right = _eval_expr(node.right, parent, linkage, comp_name, comp)

        def score(ev: ExprEval) -> tuple[int, int]:
            return (
                sum(1 for i in ev.issues if i.severity == "error"),
                sum(1 for i in ev.issues if i.severity == "warning"),
            )

        best, other = (left, right) if score(left) <= score(right) else (right, left)
        best_err = score(best)[0]
        other_err = score(other)[0]
        if best_err == 0 and (other_err > 0 or score(other)[1] > 0):
            best.issues.append(Draft(
                "info", "OR_BRANCH_SELECTABLE",
                f"组件 {comp_name} 为双重许可：选择分支 {best.branch_label} "
                f"即可合规；另一分支 {other.branch_label} 存在"
                f"{'冲突' if other_err else '告警'}，分发时应明确所选许可",
                [],
                {
                    "kind": "choose_branch",
                    "detail": f"在清单中将该组件许可固定为 "
                              f"{best.branch_label}",
                    "component": comp_name,
                },
                flavor="info",
            ))
        elif best_err > 0 and other_err > 0:
            best.issues = list(best.issues) + [Draft(
                "info", "OR_BRANCH_ALL_BLOCKED",
                f"组件 {comp_name} 的双重许可分支 {best.branch_label} 与 "
                f"{other.branch_label} 均无法在当前路径下合规",
                [], flavor="info",
            )]
        return best

    # AND：顺序累积，出站许可沿叶子链传播。
    assert isinstance(node, And)
    left = _eval_expr(node.left, parent, linkage, comp_name, comp)
    state = left.state if left.state is not None else parent
    right = _eval_expr(node.right, state, linkage, comp_name, comp)
    return ExprEval(
        left.issues + right.issues,
        right.state if right.state is not None else state,
        f"{left.branch_label} AND {right.branch_label}",
    )


# ---------------------------------------------------------------------------
# 场景与路径遍历
# ---------------------------------------------------------------------------

@dataclass
class Ctx:
    comps: dict[str, ComponentIn]
    adj: dict[str, list[object]]
    options: object
    paths_scanned: int = 0
    max_paths_reached: bool = False
    limit_notice_emitted: bool = False


def _root_scenario(project_name: str, group: list[Leaf]):
    """根 AND 组：从 NEUTRAL 起点顺序组合叶子，返回 (issues, state)。

    根只声明项目自身发布许可：保留 error/warning（如 AND 组内部冲突），
    抑制归属/源码提供等 info/notice——这些义务随依赖节点报告。
    """
    state = NEUTRAL
    issues: list[Draft] = []
    for leaf in group:
        ev = _assess_leaf(leaf, state, "static", project_name, None)
        issues.extend(d for d in ev.issues if d.severity in
                      ("error", "warning"))
        if ev.state is not None:
            state = ev.state
    return issues, state


def _walk(ctx: Ctx, node: str, state: LState, path: list[str],
          edge: Optional[tuple[str, str]], linkage: str, depth: int,
          findings: list[dict]) -> None:
    # 节点许可证表达式求值。
    comp = ctx.comps[node]
    ast = parse_spdx(comp.license)
    ev = _eval_expr(ast, state, linkage, node, comp)
    for draft in ev.issues:
        findings.append(_bind(draft, path, edge))

    new_state = ev.state if ev.state is not None else state
    _enumerate_edges(ctx, node, new_state, path, depth, findings,
                     blocked=any(i.severity == "error" for i in ev.issues))


def _enumerate_edges(ctx: Ctx, node: str, new_state: LState,
                     path: list[str], depth: int, findings: list[dict],
                     blocked: bool) -> None:
    """枚举出边并计数；blocked 时仅计数不继续下钻（避免同一冲突刷屏）。"""
    if depth >= MAX_DEPTH:
        return
    for e in ctx.adj.get(node, []):
        if e.scope != "runtime":
            continue
        ctx.paths_scanned += 1
        child_path = path + [e.to_node]
        if e.to_node in path:
            cycle_lic = comps_first_license(ctx, e.to_node)
            findings.append(_bind(Draft(
                "warning", "CYCLE_DETECTED",
                f"依赖路径存在环：{e.from_node} -> {e.to_node}，"
                "已在环处截断；环内组件请人工确认传播结果",
                [license_clause(cycle_lic)] if cycle_lic else [],
            ), child_path, (e.from_node, e.to_node)))
            continue
        if ctx.paths_scanned > ctx.options.max_paths:
            ctx.max_paths_reached = True
            if not ctx.limit_notice_emitted:
                ctx.limit_notice_emitted = True
                findings.append(_bind(Draft(
                    "warning", "PATH_LIMIT_REACHED",
                    f"已达到 max_paths={ctx.options.max_paths} 上限，"
                    "剩余路径未审计，请增大上限或拆分依赖图",
                    [],
                ), child_path, (e.from_node, e.to_node)))
            return
        if blocked:
            continue
        _walk(ctx, e.to_node, new_state, child_path,
              (e.from_node, e.to_node), e.linkage, depth + 1, findings)


def comps_first_license(ctx: Ctx, name: str) -> Optional[str]:
    comp = ctx.comps.get(name)
    if comp is None:
        return None
    token = comp.license.strip().split()[0].strip("()")
    return token if get_license(token) is not None else None


def _bind(draft: Draft, path: list[str],
          edge: Optional[tuple[str, str]]) -> dict:
    return {
        "severity": draft.severity,
        "code": draft.code,
        "message": draft.message,
        "clauses": draft.clauses,
        "resolution": draft.resolution,
        "flavor": draft.flavor,
        "path": list(path),
        "edge": list(edge) if edge else None,
    }


# ---------------------------------------------------------------------------
# 审计入口
# ---------------------------------------------------------------------------

def run_audit(req: AuditRequest) -> dict:
    comps = validate_request(req)
    project = req.project.name

    adj: dict[str, list[object]] = {project: [], **{n: [] for n in comps}}
    for e in req.graph:
        adj.setdefault(e.from_node, []).append(e)

    ctx = Ctx(comps=comps, adj=adj, options=req.options)

    root_ast = parse_spdx(req.project.release_license)
    scenarios = dnf_groups(root_ast)

    merged: dict[tuple, dict] = {}
    scenario_labels: list[str] = []
    reachable: set[str] = set()

    for group in scenarios:
        label = " AND ".join(leaf.label for leaf in group)
        scenario_labels.append(label)
        root_issues, root_state = _root_scenario(project, group)
        scenario_findings: list[dict] = []
        for d in root_issues:
            scenario_findings.append(_bind(d, [project], None))

        root_has_error = any(d.severity == "error" for d in root_issues)
        if not root_has_error:
            root_findings: list[dict] = []
            _enumerate_edges(ctx, project, root_state, [project], 0,
                             root_findings, blocked=False)
            scenario_findings.extend(root_findings)
        _collect_reachable(project, adj, reachable)

        for f in scenario_findings:
            key = (f["severity"], f["code"], tuple(f["path"]),
                   tuple(f["edge"]) if f["edge"] else None, f["message"])
            if key in merged:
                merged[key]["scenarios"].add(label)
            else:
                f["scenarios"] = {label}
                merged[key] = f

    # 不可达组件（不与项目根连通，或仅经 test/build 边可达）。
    for name in comps:
        if name not in reachable:
            key = ("info", "UNREACHABLE_COMPONENT", (project, name),
                   None, f"组件 {name} 不在自项目根出发的任何 runtime 依赖"
                         "路径上，未参与本次发布许可传播审计")
            if key not in merged:
                merged[key] = {
                    "severity": "info",
                    "code": "UNREACHABLE_COMPONENT",
                    "message": key[4],
                    "clauses": [],
                    "resolution": None,
                    "flavor": "info",
                    "path": [project, name],
                    "edge": None,
                    "scenarios": {label for label in scenario_labels},
                }

    findings = list(merged.values())
    # 场景标注。
    for f in findings:
        labels = sorted(f.pop("scenarios"))
        f["scenario"] = (
            labels[0] if len(labels) == 1
            else " | ".join(labels) if len(labels) < len(scenario_labels)
            else None
        )

    # 选项过滤。
    def keep(f: dict) -> bool:
        if f["severity"] == "error" or f["severity"] == "warning":
            return True
        if f["flavor"] == "notice":
            return req.options.include_notices
        return req.options.include_info

    findings = [f for f in findings if keep(f)]
    rank = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: (rank[f["severity"]], f["path"], f["code"]))

    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    infos = sum(1 for f in findings if f["severity"] == "info")
    status = "conflict" if errors else ("warnings" if warnings else "compliant")

    return {
        "status": status,
        "summary": {
            "paths_scanned": ctx.paths_scanned,
            "max_paths_reached": ctx.max_paths_reached,
            "errors": errors,
            "warnings": warnings,
            "infos": infos,
            "components": len(comps),
            "edges": len(req.graph),
            "scenarios": scenario_labels,
            "status": status,
        },
        "findings": findings,
    }


def _collect_reachable(project: str,
                       adj: dict[str, list], acc: set[str]) -> None:
    stack = [project]
    seen = {project}
    while stack:
        cur = stack.pop()
        for e in adj.get(cur, []):
            if e.scope != "runtime":
                continue
            acc.add(e.to_node)
            if e.to_node not in seen:
                seen.add(e.to_node)
                stack.append(e.to_node)
