"""内置许可证规则库。

审计引擎基于一个简化但覆盖常见 SPDX 许可证的兼容性模型，
关键维度：

* copyleft: 宽松 / 弱(库级) / 强(作品级) / 网络级 / 专有 / 未知
* gpl_compatible_with: 该许可证可与哪些强/网络 copyleft 许可证组合
* name / clause: 触发冲突时向用户展示的许可证全称与条款名

模型刻意保持可读、可扩展，不追求与 FSF/OSI 清单逐字节一致；
生产环境可将 LICENSES 替换为数据库或外部规则服务。
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class Copyleft(str, Enum):
    PERMISSIVE = "permissive"   # 宽松许可证
    WEAK = "weak"               # 弱 copyleft（LGPL/MPL/EPL/CDDL 等）
    STRONG = "strong"           # 强 copyleft（GPL）
    NETWORK = "network"         # 网络 copyleft（AGPL）
    PROPRIETARY = "proprietary" # 专有商业许可
    UNKNOWN = "unknown"         # LicenseRef / 未识别 id


class LicenseInfo(BaseModel):
    spdx_id: str
    name: str
    copyleft: Copyleft
    # 可作为强/网络 copyleft 项目的组成部分（含与 GPL-2.0-only 的特殊兼容）
    gpl_compatible_with: frozenset[str] = frozenset()
    # 许可证来源约束的代表性条款（用于冲突报告）
    clause: str = ""
    # 专利保护类条款（对 GPL-2.0-only 构成冲突的特殊情况）
    patent_clause: bool = False

    model_config = ConfigDict(frozen=True)


# GPL / AGPL 家族常量
_GPL2_ONLY = "GPL-2.0-only"
_GPL2_LATER = "GPL-2.0-or-later"
_GPL3_ONLY = "GPL-3.0-only"
_GPL3_LATER = "GPL-3.0-or-later"
_AGPL3_ONLY = "AGPL-3.0-only"
_AGPL3_LATER = "AGPL-3.0-or-later"

_GPL3_FAMILY = frozenset({_GPL3_ONLY, _GPL3_LATER, _AGPL3_ONLY, _AGPL3_LATER})
_GPL_ANY = frozenset(
    {_GPL2_ONLY, _GPL2_LATER, _GPL3_ONLY, _GPL3_LATER, _AGPL3_ONLY, _AGPL3_LATER}
)

_PERMISSIVE_INFO = dict(copyleft=Copyleft.PERMISSIVE)


def _lic(
    spdx_id: str,
    name: str,
    *,
    copyleft: Copyleft,
    clause: str,
    gpl_compatible_with: frozenset[str] = frozenset(),
    patent_clause: bool = False,
) -> LicenseInfo:
    return LicenseInfo(
        spdx_id=spdx_id,
        name=name,
        copyleft=copyleft,
        clause=clause,
        gpl_compatible_with=frozenset(gpl_compatible_with),
        patent_clause=patent_clause,
    )


LICENSES: dict[str, LicenseInfo] = {
    # ---- 宽松许可证 ----
    "MIT": _lic("MIT", "MIT License", clause="License and Copyright Notice",
                **_PERMISSIVE_INFO),
    "MIT-0": _lic("MIT-0", "MIT No Attribution", clause="No notice required",
                  **_PERMISSIVE_INFO),
    "ISC": _lic("ISC", "ISC License", clause="License and Copyright Notice",
                **_PERMISSIVE_INFO),
    "BSD-2-Clause": _lic("BSD-2-Clause", "BSD 2-Clause \"Simplified\" License",
                         clause="Redistribution and use conditions", **_PERMISSIVE_INFO),
    "BSD-3-Clause": _lic("BSD-3-Clause", "BSD 3-Clause License",
                         clause="Redistribution and use conditions", **_PERMISSIVE_INFO),
    "Apache-2.0": _lic(
        "Apache-2.0", "Apache License 2.0",
        clause="Distribution Requirements (NOTICE)",
        gpl_compatible_with=_GPL3_FAMILY,  # 专利条款与 GPL-2.0-only 不兼容
        patent_clause=True, **_PERMISSIVE_INFO,
    ),
    "Zlib": _lic("Zlib", "zlib License", clause="Source redistribution conditions",
                 **_PERMISSIVE_INFO),
    "Unlicense": _lic("Unlicense", "The Unlicense", clause="Public-domain dedication",
                      **_PERMISSIVE_INFO),
    "Python-2.0": _lic("Python-2.0", "Python License 2.0",
                       clause="License and Copyright Notice",
                       gpl_compatible_with=_GPL_ANY, **_PERMISSIVE_INFO),
    "PSF-2.0": _lic("PSF-2.0", "Python Software Foundation License 2.0",
                    clause="License and Copyright Notice",
                    gpl_compatible_with=_GPL_ANY, **_PERMISSIVE_INFO),
    "BSL-1.1": _lic("BSL-1.1", "Boost Software License 1.1",
                    clause="License and Copyright Notice",
                    gpl_compatible_with=_GPL_ANY, **_PERMISSIVE_INFO),
    "0BSD": _lic("0BSD", "BSD Zero Clause License", clause="No notice required",
                 gpl_compatible_with=_GPL_ANY, **_PERMISSIVE_INFO),
    "CC0-1.0": _lic("CC0-1.0", "Creative Commons Zero v1.0 Universal",
                    clause="Public-domain dedication", **_PERMISSIVE_INFO),
    "CC-BY-4.0": _lic("CC-BY-4.0", "Creative Commons Attribution 4.0",
                      clause="Attribution", **_PERMISSIVE_INFO),

    # ---- 弱 copyleft ----
    "MPL-2.0": _lic(
        "MPL-2.0", "Mozilla Public License 2.0",
        copyleft=Copyleft.WEAK,
        clause="MPL 2.0 Section 3.3 (Distribution of Modifiable Form)",
        gpl_compatible_with=_GPL3_FAMILY,  # MPL 2.0 §3.3 明确允许与 GPLv3 二级许可组合
    ),
    "LGPL-2.1-only": _lic(
        "LGPL-2.1-only", "GNU Lesser General Public License v2.1 only",
        copyleft=Copyleft.WEAK,
        clause="LGPL-2.1 §6 (Combined Works; relink obligation)",
    ),
    "LGPL-2.1-or-later": _lic(
        "LGPL-2.1-or-later", "GNU LGPL v2.1 or later",
        copyleft=Copyleft.WEAK,
        clause="LGPL-2.1 §6 (Combined Works; relink obligation)",
        gpl_compatible_with={_GPL2_ONLY, _GPL2_LATER, _GPL3_ONLY, _GPL3_LATER},
    ),
    "LGPL-3.0-only": _lic(
        "LGPL-3.0-only", "GNU Lesser General Public License v3.0 only",
        copyleft=Copyleft.WEAK,
        clause="LGPL-3.0 §4 (Combined Works; relink obligation)",
        gpl_compatible_with={_GPL3_ONLY, _GPL3_LATER, _AGPL3_ONLY, _AGPL3_LATER},
    ),
    "LGPL-3.0-or-later": _lic(
        "LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later",
        copyleft=Copyleft.WEAK,
        clause="LGPL-3.0 §4 (Combined Works; relink obligation)",
        gpl_compatible_with={_GPL3_ONLY, _GPL3_LATER, _AGPL3_ONLY, _AGPL3_LATER},
    ),
    "EPL-1.0": _lic(
        "EPL-1.0", "Eclipse Public License 1.0",
        copyleft=Copyleft.WEAK,
        clause="EPL-1.0 §3 (Contributor Version; source availability)",
    ),
    "EPL-2.0": _lic(
        "EPL-2.0", "Eclipse Public License 2.0",
        copyleft=Copyleft.WEAK,
        clause="EPL-2.0 §3.1 (Source Code Availability)",
        gpl_compatible_with=_GPL3_FAMILY,  # EPL-2.0 含 GPL 兼容二级许可
    ),
    "CDDL-1.0": _lic(
        "CDDL-1.0", "Common Development and Distribution License 1.0",
        copyleft=Copyleft.WEAK,
        clause="CDDL-1.0 §3.1 (Source Code Availability)",
    ),
    "CDDL-1.1": _lic(
        "CDDL-1.1", "Common Development and Distribution License 1.1",
        copyleft=Copyleft.WEAK,
        clause="CDDL-1.1 §3.1 (Source Code Availability)",
    ),

    # ---- 强 copyleft（GPL 家族）----
    _GPL2_ONLY: _lic(
        _GPL2_ONLY, "GNU General Public License v2.0 only",
        copyleft=Copyleft.STRONG,
        clause="GPL-2.0 §2(b) (whole work under GPL) & §3 (source offer)",
        gpl_compatible_with={_GPL2_ONLY},
    ),
    _GPL2_LATER: _lic(
        _GPL2_LATER, "GNU General Public License v2.0 or later",
        copyleft=Copyleft.STRONG,
        clause="GPL-2.0 §2(b) (whole work under GPL) & §3 (source offer)",
        # "or-later" 可升级至 GPLv3，进而单向并入 AGPLv3
        gpl_compatible_with={_GPL2_ONLY, _GPL2_LATER, _GPL3_ONLY, _GPL3_LATER,
                             _AGPL3_ONLY, _AGPL3_LATER},
    ),
    _GPL3_ONLY: _lic(
        _GPL3_ONLY, "GNU General Public License v3.0 only",
        copyleft=Copyleft.STRONG,
        clause="GPL-3.0 §5 (Conveying Modified Source Versions)",
        # FSF：GPLv3 代码允许以 AGPLv3 条款并入 AGPL 作品（单向兼容）
        gpl_compatible_with={_GPL3_ONLY, _GPL3_LATER, _AGPL3_ONLY, _AGPL3_LATER},
    ),
    _GPL3_LATER: _lic(
        _GPL3_LATER, "GNU General Public License v3.0 or later",
        copyleft=Copyleft.STRONG,
        clause="GPL-3.0 §5 (Conveying Modified Source Versions)",
        gpl_compatible_with={_GPL3_ONLY, _GPL3_LATER, _AGPL3_ONLY, _AGPL3_LATER},
    ),

    # ---- 网络 copyleft ----
    _AGPL3_ONLY: _lic(
        _AGPL3_ONLY, "GNU Affero General Public License v3.0 only",
        copyleft=Copyleft.NETWORK,
        clause="AGPL-3.0 §13 (Remote Network Interaction; source offer)",
        gpl_compatible_with={_AGPL3_ONLY},
    ),
    _AGPL3_LATER: _lic(
        _AGPL3_LATER, "GNU Affero General Public License v3.0 or later",
        copyleft=Copyleft.NETWORK,
        clause="AGPL-3.0 §13 (Remote Network Interaction; source offer)",
        gpl_compatible_with={_AGPL3_ONLY, _AGPL3_LATER},
    ),

    # ---- 源码可得 / 特殊 ----
    "SSPL-1.0": _lic(
        "SSPL-1.0", "Server Side Public License 1.0",
        copyleft=Copyleft.NETWORK,
        clause="SSPL §13 (Service Source Code release obligation)",
    ),
    "Elastic-2.0": _lic(
        "Elastic-2.0", "Elastic License 2.0",
        copyleft=Copyleft.PROPRIETARY,
        clause="Elastic-2.0 restrictions (hosting; providing managed service)",
    ),
}


# SPDX 链接例外 / 宽松例外：随强 copyleft 许可证出现时，
# 将“作品级 copyleft 传染”降级为 LGPL 式的弱 copyleft 义务
STRONG_COPYLEFT_EXCEPTIONS: frozenset[str] = frozenset({
    "Classpath-exception-2.0",
    "GCC-exception-2.0",
    "GCC-exception-3.1",
    "LGPL-3.0-linking-exception",
    "LGPL-3.0-linking-source-exception",
    "OCaml-LGPL-linking-exception",
    "openvpn-openssl-exception",
    "u-boot-exception-2.0",
    "Linux-syscall-note",
})

# 常见但不改变 copyleft 强度的例外（识别但不降级，仅在审计中透传）
KNOWN_EXCEPTIONS: frozenset[str] = STRONG_COPYLEFT_EXCEPTIONS | frozenset({
    "Autoconf-exception-2.0",
    "Autoconf-exception-3.0",
    "Bison-exception-2.2",
    "FLTK-exception",
    "Font-exception-2.0",
    "Libtool-exception",
    "Bootloader-exception",
    "GPL-3.0-linking-exception",
    "GPL-CC-1.0",
})


_PROPRIETARY = LicenseInfo(
    spdx_id="LicenseRef-Proprietary",
    name="Proprietary / Commercial License",
    copyleft=Copyleft.PROPRIETARY,
    clause="Proprietary license terms (no redistribution / source grant)",
)


def get_license(spdx_id: str) -> LicenseInfo | None:
    """按 SPDX id 查询规则；未知 id 返回 None（解析期会标记 unknown）。"""
    if spdx_id == "LicenseRef-Proprietary":
        return _PROPRIETARY
    return LICENSES.get(spdx_id)
