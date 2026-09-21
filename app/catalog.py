"""内置 SPDX 许可证目录与许可证例外目录。

许可证分为五类（``category``）：

- ``permissive``   宽松许可（MIT/Apache/BSD 等）
- ``weak_copyleft`` 弱著佐权（LGPL/MPL/EPL/CDDL），链接边界内不传染
- ``strong_copyleft`` 强著佐权（GPL），整体衍生作品需同许可
- ``network``      网络著佐权（AGPL），网络交互即触发源码提供
- ``proprietary``  专有/商业许可
- ``public``       公共领域/接近放弃权利（CC0/Unlicense）

弱著佐权条目的 ``gpl_family``/``gpl_versions``/``agpl_versions``
描述其可与哪些版本的 GPL/AGPL 组合；``version`` 用于版本号比较，
``or_later`` 表示 -or-later 后缀。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

LICENSE_URL = "https://spdx.org/licenses/{lid}.html"
EXCEPTION_URL = "https://spdx.org/licenses/{eid}.html"


@dataclass(frozen=True)
class LicenseInfo:
    spdx_id: str
    name: str
    category: str
    # 弱著佐权 -> GPL 兼容矩阵
    gpl_family: bool = False
    gpl_versions: Optional[tuple[int, ...]] = None
    agpl_versions: Optional[tuple[int, ...]] = None
    gpl_version: Optional[int] = None  # 强/网络著佐权自身的 GPL 版本
    or_later: bool = False
    section: str = ""
    patent_section: Optional[str] = None
    notice_section: Optional[str] = None
    source_section: Optional[str] = None
    network_section: Optional[str] = None


@dataclass(frozen=True)
class ExceptionInfo:
    exception_id: str
    name: str
    effect: str  # linking_relaxed / output_exempt / notice_only / unknown
    section: str


# ---------------------------------------------------------------------------
# 条款章节（取自各许可证通行的章节标题/编号）
# ---------------------------------------------------------------------------

_PERMISSIVE = {
    # spdx_id: (显示名, 主条款, 归属/声明条款)
    "MIT": ("MIT License", "许可证全文（许可与免责声明）", "保留版权与许可声明"),
    "ISC": ("ISC License", "许可证全文（授权条款）", "保留版权与许可声明"),
    "0BSD": ("BSD Zero Clause License", "第1条 免责声明", None),
    "BSD-2-Clause": ("BSD 2-Clause Simplified License", "第1-2条 再分发条件", "第1条 保留版权声明"),
    "BSD-3-Clause": ("BSD 3-Clause New or Revised License", "第1-3条 再分发条件", "第1条 保留版权声明"),
    "Apache-2.0": ("Apache License 2.0", "第1-9条 许可、再分发与商标", "第4条 再分发（保留 NOTICE）"),
    "Zlib": ("zlib License", "许可证全文（再分发条件）", "第1条 不得虚假声明来源"),
    "BSL-1.0": ("Boost Software License 1.0", "第1条 授权", None),
    "Python-2.0": ("Python License 2.0", "第3条 许可授予", None),
    "PSF-2.0": ("Python Software Foundation License 2.0", "第3条 许可授予", None),
    "PostgreSQL": ("PostgreSQL License", "许可证全文", "保留版权声明"),
    "X11": ("X11 License", "许可证全文", "保留版权声明"),
}

_WEAK = {
    # spdx_id: (显示名, gpl_versions, agpl_versions, 主条款, 源码条款)
    "LGPL-2.0-only": ("GNU LGPL v2", (2,), (), "第6条 组合作品", "第6条 提供可重新链接的目标文件"),
    "LGPL-2.0-or-later": ("GNU LGPL v2 or later", (2, 3), (3,), "第6条 组合作品（按更高版本）", "第6条 提供可重新链接的目标文件"),
    "LGPL-2.1-only": ("GNU LGPL v2.1", (2,), (), "第6条 组合作品", "第6条 提供可重新链接的目标文件"),
    "LGPL-2.1-or-later": ("GNU LGPL v2.1 or later", (2, 3), (3,), "第6条 组合作品（按更高版本）", "第6条 提供可重新链接的目标文件"),
    "LGPL-3.0-only": ("GNU LGPL v3", (3,), (3,), "第4条 组合作品", "第4条(d) 提供链接所需材料"),
    "LGPL-3.0-or-later": ("GNU LGPL v3 or later", (3,), (3,), "第4条 组合作品（按更高版本）", "第4条(d) 提供链接所需材料"),
    "MPL-1.1": ("Mozilla Public License 1.1", (), (), "第13条 对源代码修改的许可", "第3条 源代码形式分发义务"),
    "MPL-2.0": ("Mozilla Public License 2.0", (3,), (3,), "第3.3条 较大作品的分发", "第3.2条 源代码形式的可获得性"),
    "EPL-1.0": ("Eclipse Public License 1.0", (), (), "第3条 要求", "第3条 提供源代码"),
    "EPL-2.0": ("Eclipse Public License 2.0", (3,), (3,), "第3条 要求", "第3.1条 提供源代码"),
    "CDDL-1.0": ("Common Development and Distribution License 1.0", (), (), "第3条 分发要求", "第3.1条 源代码可获得性"),
    "CDDL-1.1": ("Common Development and Distribution License 1.1", (), (), "第3条 分发要求", "第3.1条 源代码可获得性"),
    "CPL-1.0": ("Common Public License 1.0", (), (), "第3条 分发要求", "第3条 提供源代码"),
}

_STRONG = {
    "GPL-1.0-only": ("GNU GPL v1", 1, False, "第3条 复制、分发与修改", None),
    "GPL-1.0-or-later": ("GNU GPL v1 or later", 1, True, "第3条 复制、分发与修改（按更高版本）", None),
    "GPL-2.0-only": ("GNU GPL v2", 2, False, "第2条 衍生作品整体许可", "第3条 源代码提供义务"),
    "GPL-2.0-or-later": ("GNU GPL v2 or later", 2, True, "第2条 衍生作品整体许可（可升级至v3）", "第3条 源代码提供义务"),
    "GPL-3.0-only": ("GNU GPL v3", 3, False, "第5条  conveying 基于本程序的作品", "第6条 以源代码形式提供"),
    "GPL-3.0-or-later": ("GNU GPL v3 or later", 3, True, "第5条 传播基于本程序的作品（按更高版本）", "第6条 以源代码形式提供"),
}

_NETWORK = {
    "AGPL-3.0-only": ("GNU AGPL v3", 3, False, "第13条 远程网络交互", "第13条 向网络用户提供对应源代码"),
    "AGPL-3.0-or-later": ("GNU AGPL v3 or later", 3, True, "第13条 远程网络交互（按更高版本）", "第13条 向网络用户提供对应源代码"),
}

_PUBLIC = {
    "CC0-1.0": ("Creative Commons Zero v1.0 Universal", "第2条 放弃权利", None),
    "Unlicense": ("The Unlicense", "全文（放弃版权）", None),
}


def _build() -> dict[str, LicenseInfo]:
    info: dict[str, LicenseInfo] = {}
    for lid, (name, section, notice) in _PERMISSIVE.items():
        info[lid] = LicenseInfo(
            spdx_id=lid,
            name=name,
            category="permissive",
            section=section,
            notice_section=notice,
            patent_section="第3条 专利授权" if lid == "Apache-2.0" else None,
        )
    for lid, (name, gplv, agplv, section, source) in _WEAK.items():
        or_later = lid.endswith("-or-later")
        info[lid] = LicenseInfo(
            spdx_id=lid,
            name=name,
            category="weak_copyleft",
            gpl_family=lid.startswith("LGPL"),
            gpl_versions=gplv,
            agpl_versions=agplv,
            section=section,
            source_section=source,
            or_later=or_later,
        )
    for lid, (name, ver, or_later, section, source) in _STRONG.items():
        info[lid] = LicenseInfo(
            spdx_id=lid,
            name=name,
            category="strong_copyleft",
            gpl_version=ver,
            or_later=or_later,
            section=section,
            source_section=source,
        )
    for lid, (name, ver, or_later, section, source) in _NETWORK.items():
        info[lid] = LicenseInfo(
            spdx_id=lid,
            name=name,
            category="network",
            gpl_version=ver,
            or_later=or_later,
            section=section,
            source_section=source,
            network_section="第13条 远程网络交互",
        )
    for lid, (name, section, notice) in _PUBLIC.items():
        info[lid] = LicenseInfo(
            spdx_id=lid, name=name, category="public", section=section,
            notice_section=notice,
        )
    info["LicenseRef-Proprietary"] = LicenseInfo(
        spdx_id="LicenseRef-Proprietary",
        name="Proprietary / Commercial License",
        category="proprietary",
        section="专有许可证条款",
    )
    return info


LICENSES: dict[str, LicenseInfo] = _build()

# 特殊原子
SPECIAL = {
    "NONE": LicenseInfo("NONE", "No license (SPDX NONE)", "none", section="SPDX NONE"),
    "NOASSERTION": LicenseInfo(
        "NOASSERTION", "License not asserted (SPDX NOASSERTION)", "noassertion",
        section="SPDX NOASSERTION",
    ),
}

# ---------------------------------------------------------------------------
# 许可证例外
# ---------------------------------------------------------------------------

EXCEPTIONS: dict[str, ExceptionInfo] = {
    "Classpath-exception-2.0": ExceptionInfo(
        "Classpath-exception-2.0", "Classpath exception 2.0", "linking_relaxed",
        "例外全文（链接例外，允许与独立模块链接）",
    ),
    "GCC-exception-2.0": ExceptionInfo(
        "GCC-exception-2.0", "GCC Runtime Library exception 2.0", "output_exempt",
        "例外全文（编译器输出不传染）",
    ),
    "GCC-exception-3.1": ExceptionInfo(
        "GCC-exception-3.1", "GCC Runtime Library exception 3.1", "output_exempt",
        "例外全文（编译器输出不传染）",
    ),
    "Autoconf-exception-2.0": ExceptionInfo(
        "Autoconf-exception-2.0", "Autoconf exception 2.0", "output_exempt",
        "例外全文（生成的 configure 脚本不传染）",
    ),
    "Autoconf-exception-3.0": ExceptionInfo(
        "Autoconf-exception-3.0", "Autoconf exception 3.0", "output_exempt",
        "例外全文（生成的 configure 脚本不传染）",
    ),
    "Nokia-Qt-exception-1.1": ExceptionInfo(
        "Nokia-Qt-exception-1.1", "Nokia Qt LGPL exception 1.1", "linking_relaxed",
        "例外全文（放宽 LGPL 链接条件）",
    ),
    "Linux-syscall-note": ExceptionInfo(
        "Linux-syscall-note", "Linux Syscall Note", "linking_relaxed",
        "例外全文（系统调用不构成衍生作品）",
    ),
    "LLVM-exception": ExceptionInfo(
        "LLVM-exception", "LLVM exception", "linking_relaxed",
        "例外全文（Apache-2.0 链接例外）",
    ),
    "Font-exception-2.0": ExceptionInfo(
        "Font-exception-2.0", "Font exception 2.0", "notice_only",
        "例外全文（字体嵌入例外）",
    ),
    "OCaml-LGPL-linking-exception": ExceptionInfo(
        "OCaml-LGPL-linking-exception", "OCaml LGPL Linking Exception",
        "linking_relaxed", "例外全文（放宽静态链接条件）",
    ),
    "Universal-FOSS-exception-1.0": ExceptionInfo(
        "Universal-FOSS-exception-1.0", "Universal FOSS Exception 1.0",
        "linking_relaxed", "例外全文（GPL 兼容性链接例外）",
    ),
    "Bootloader-exception": ExceptionInfo(
        "Bootloader-exception", "Bootloader Distribution Exception",
        "linking_relaxed", "例外全文（引导程序分发例外）",
    ),
}

_LINKING_RELAXED = {
    eid for eid, ex in EXCEPTIONS.items() if ex.effect == "linking_relaxed"
}

_VERSION_RE = re.compile(r"^(?P<family>[A-Z]+)-(?P<version>\d(?:\.\d+)?)-(?P<tail>.+)$")


@dataclass(frozen=True)
class VersionedLicense:
    """GPL 家族许可证的版本解析结果。"""

    family: str   # GPL / LGPL / AGPL
    version: int  # 主版本号
    or_later: bool


def parse_versioned(spdx_id: str) -> Optional[VersionedLicense]:
    m = _VERSION_RE.match(spdx_id)
    if not m:
        return None
    family = m.group("family")
    if family not in ("GPL", "LGPL", "AGPL"):
        return None
    try:
        major = int(m.group("version").split(".")[0])
    except ValueError:
        return None
    tail = m.group("tail")
    if tail not in ("only", "or-later"):
        return None
    return VersionedLicense(family, major, tail == "or-later")


def get_license(spdx_id: str) -> Optional[LicenseInfo]:
    if spdx_id in SPECIAL:
        return SPECIAL[spdx_id]
    return LICENSES.get(spdx_id)


def classify(spdx_id: str) -> str:
    """未知 LicenseRef 的启发式分类。"""
    info = get_license(spdx_id)
    if info is not None:
        return info.category
    if spdx_id.startswith(("LicenseRef-", "DocumentRef-")):
        upper = spdx_id.upper()
        if "PROPRIETARY" in upper or "COMMERCIAL" in upper:
            return "proprietary"
        return "unknown"
    return "unknown"


def linking_relaxed(exception: Optional[str]) -> bool:
    return exception in _LINKING_RELAXED


def license_clause(lid: str, section: Optional[str] = None) -> dict:
    info = get_license(lid)
    sec = section or (info.section if info else "许可证全文")
    return {
        "license_id": lid,
        "section": sec,
        "url": LICENSE_URL.format(lid=lid),
    }


def exception_clause(eid: str) -> dict:
    ex = EXCEPTIONS.get(eid)
    return {
        "license_id": eid,
        "section": ex.section if ex else "许可证例外全文",
        "url": EXCEPTION_URL.format(eid=eid),
    }
