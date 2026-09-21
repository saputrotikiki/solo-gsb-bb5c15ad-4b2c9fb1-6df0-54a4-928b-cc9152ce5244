# 依赖许可兼容性审计 API

基于 **Python + FastAPI** 的服务：接收组件清单、依赖有向图和 SPDX 许可证表达式，
解析 `AND` / `OR` / `WITH` 组合，将**项目发布许可沿每条依赖路径传播**，
返回冲突路径、触发条款与可选替换节点；提供**幂等审计接口**与 OpenAPI 文档。

- Web 框架：FastAPI + Pydantic v2 + Uvicorn
- 表达式：内置 SPDX 表达式解析器（`AND`/`OR`/`WITH`、括号、`+` 后缀）
- 部署：Dockerfile + docker compose 一键启动，监听 **8000** 端口

> ⚠️ 审计结果是工程辅助信息，**不构成法律意见**。

---

## 目录

- [快速启动](#快速启动)
- [本地开发](#本地开发)
- [接口说明](#接口说明)
- [请求模型](#请求模型)
- [审计规则与边界](#审计规则与边界)
- [内置许可证与例外目录](#内置许可证与例外目录)
- [配置项](#配置项)
- [测试](#测试)
- [项目结构](#项目结构)

---

## 快速启动

前置条件：已安装 Docker 与 Docker Compose（`docker compose version` 可用）。

```bash
# 在仓库根目录
docker compose up --build -d
```

服务启动后监听 **8000** 端口：

| 用途 | 地址 |
| --- | --- |
| Swagger UI（可在线调试） | http://localhost:8000/docs |
| ReDoc 文档 | http://localhost:8000/redoc |
| OpenAPI JSON | http://localhost:8000/openapi.json |
| 健康检查 | http://localhost:8000/health |
| 审计接口 | `POST http://localhost:8000/api/v1/audits` |

停止：

```bash
docker compose down
```

### 发起一次审计

仓库自带示例 `examples/audit_request.json`：

```bash
curl -sX POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  --data @examples/audit_request.json | python3 -m json.tool
```

示例中 `shop-backend` 以 `GPL-2.0-only` 发布，依赖了 `LGPL-3.0-only`
与一个专有 SDK，响应会给出 2 条冲突、各自触发路径、条款引用（章节 + SPDX URL）
和可选解决方式（替换组件 / 改许可 / 动态链接 / 选择 OR 分支）。

也可以打开 http://localhost:8000/docs ，在 `POST /api/v1/audits` 上直接
粘贴该 JSON 执行。

---

## 本地开发

需要 Python 3.11+。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 接口说明

所有业务接口均以 `/api/v1` 为前缀。

### `POST /api/v1/audits` — 提交审计（幂等）

- 首次提交：返回 `201 Created`，响应体 `created=true`。
- 重复提交相同请求体：返回 `200 OK`，响应体 `created=false`，
  `audit_id` 与首次结果完全一致。
- 幂等键：默认取**请求体规范化 JSON（键排序、去空白）的 SHA-256**；
  也可用请求头 `Idempotency-Key: <自定义键>` 显式指定。
- 结果保存在进程内的线程安全仓库中（LRU 容量上限 + TTL，见[配置项](#配置项)），
  多副本部署时可替换为 Redis/数据库实现（`app/store.py`）。

### `GET /api/v1/audits/{audit_id}` — 查询历史审计结果

返回该审计的完整结果；不存在或已过期返回 `404`。

### `POST /api/v1/audits/evaluate` — 无状态评估

执行同样的审计逻辑但**不写入幂等仓库**，适合 CI 流水线每次构建调用。

### `GET /health` / `GET /`

健康检查与服务信息。

### 错误信封

4xx/5xx 统一为：

```json
{ "error": { "code": "INVALID_GRAPH", "message": "...", "pointer": "project.release_license" } }
```

常见错误码：`VALIDATION_ERROR`（请求体校验）、`INVALID_GRAPH`（SPDX 解析失败、
重复边、未知节点等）、`AUDIT_NOT_FOUND`、`INTERNAL_ERROR`。

---

## 请求模型

```jsonc
{
  "project": {
    "name": "shop-backend",
    "version": "1.2.0",
    "release_license": "GPL-2.0-only OR (MIT AND Apache-2.0)"
  },
  "components": [
    {
      "name": "orders-lib",
      "version": "2.0.1",
      "license": "LGPL-3.0-only",                       // SPDX 表达式
      "replacements": [                                // 可选替换节点
        { "name": "orders-lib-2.1", "license": "LGPL-2.1-only",
          "url": "https://example.org", "note": "可转换为 GPL-2" }
      ]
    },
    { "name": "payments-sdk", "license": "LicenseRef-Proprietary" }
  ],
  "graph": [
    { "from": "shop-backend", "to": "orders-lib",
      "linkage": "dynamic", "scope": "runtime" },
    { "from": "shop-backend", "to": "payments-sdk",
      "linkage": "static",  "scope": "runtime" }
  ],
  "options": { "include_info": true, "include_notices": true, "max_paths": 2000 }
}
```

- **边的方向**：`from` 依赖 `to`，自项目根出发；`from` 可以是项目名或组件名。
- **`linkage`**：`static` / `dynamic` / `unknown`，只对弱著佐权（LGPL/MPL/EPL）
  的传播有影响。
- **`scope`**：`runtime`（默认，参与发布传播）/ `build` / `test`（不参与传播，
  仅经这些边可达的组件会得到 `UNREACHABLE_COMPONENT` 提示）。
- **`max_paths`**：路径枚举上限（1–10000，默认 2000），防止菱形/环图下指数膨胀；
  触顶时给出 `PATH_LIMIT_REACHED` 告警。

### 响应中的 `findings[]`

| 字段 | 说明 |
| --- | --- |
| `severity` | `error`（冲突）/ `warning` / `info` |
| `code` | 机器可读代码，如 `STRONG_COPYLEFT_INTO_PROPRIETARY` |
| `path` | 触发问题的完整依赖路径，项目名为起点 |
| `edge` | 触发边 `[from, to]` |
| `clauses` | 触发条款：`license_id` + 章节 + `https://spdx.org/licenses/...` |
| `scenario` | 项目发布许可 OR 分支（DNF 场景），全场景共同时为 `null` |
| `resolution` | 可选解决方式（见下） |

`resolution.kind` 取值：

- `choose_branch`：组件是双重许可（OR），选择合规分支即可；
- `use_dynamic_link`：改为动态链接，使弱著佐权许可边界成立；
- `add_exception`：可通过声明链接例外（如 `Classpath-exception-2.0`）放宽；
- `replace_component`：使用 `components[].replacements` 中已验证兼容的替换件；
- `relicense`：更改项目或该组件的发布许可。

整体 `status`：`conflict`（存在 error）/ `warnings` / `compliant`。

---

## 审计规则与边界

### 传播模型

1. 项目发布许可表达式先展开为 DNF：每个 OR 分支是一个**场景**，场景内 AND 叶子
   顺序组合，取约束最强者作为初始出站许可。
2. 自项目根沿 runtime 边做深度优先遍历；每个组件节点解析其许可证表达式
   （AND 累积、OR 选错误最少的分支并对双许可给出 `OR_BRANCH_SELECTABLE` 提示）。
3. 父节点的出站许可与本节点许可做兼容性判定，产出问题与新的出站许可继续向下传播。
4. 某节点产生 `error` 后不再向其子树传播（避免同一根因沿每条下游路径重复刷屏），
   但出边仍计入 `paths_scanned`。
5. 合并所有场景的结果：同一问题在多个场景出现时聚合，`scenario` 标注差异。

### 主要判定规则（简化的工程模型）

- **强著佐权（GPL）进入专有/闭源发布物 → 冲突**；动态链接**不**构成 GPL 的许可边界。
- **网络著佐权（AGPL）进入专有发布物 → 冲突**；附带“网络交互即须提供源码”义务。
- **GPL 兼容的宽松许可（MIT/BSD/Apache-2.0/CC0）纳入 GPL 组件**：组合作品整体
  可升级为 GPL 出站（单向兼容），但附带源码提供义务；这不是冲突。
- **Apache-2.0 ↔ GPL-2.0-only → 专利条款冲突**（`PATENT_INCOMPATIBILITY`）；
  Apache-2.0 与 GPL-3.0 兼容。
- **弱著佐权（LGPL/MPL/EPL/CDDL）**：
  - 进入专有发布物：**动态链接**构成许可边界，合规（附带重新链接/源码材料义务）；
    **静态链接**触发冲突，建议动态链接或替换。
  - 进入 GPL 作品：按“可转换的 GPL/AGPL 版本矩阵”判定，例如 LGPL-3.0 只能
    转换到 GPL-3，不能进入 GPL-2-only 项目；LGPL-2.1 可转换到 GPL-2。
- **GPL/AGPL 版本组合**：同版本兼容；任一方 `-or-later` 可升级；否则
  `GPL_VERSION_MISMATCH`。GPL 与 AGPL 仅在可统一到 v3 时依 AGPL-3.0 第13条
  交叉许可。
- **链接例外（WITH）**：`Classpath-exception-2.0`、`Nokia-Qt-exception-1.1`、
  `LLVM-exception` 等放宽静态链接的传染；`GCC-exception-*`、`Autoconf-exception-*`
  属于“生成物不传染”。目录外例外不假设放宽（`UNKNOWN_EXCEPTION` 提示）。
- **`NONE` / `NOASSERTION` / 未知 LicenseRef**：产生告警，根节点按最保守的
  专有约束处理。
- **环**：在路径上截断并告警（`CYCLE_DETECTED`）。

刻意简化之处：传播方向为“项目发布许可自上而下”，不做反向传染推断；链接边界只对
弱著佐权成立；许可证义务（源码提供、归属声明）以 `info`/`notice` 提示，可通过
`options` 关闭。涉及具体发布决策时请由法务复核。

---

## 内置许可证与例外目录

- 宽松/公共领域：MIT、ISC、0BSD、BSD-2/3-Clause、Apache-2.0、Zlib、BSL-1.0、
  Python-2.0、PSF-2.0、PostgreSQL、X11、CC0-1.0、Unlicense
- 弱著佐权：LGPL-2.0/2.1/3.0（`-only`/`-or-later`）、MPL-1.1、MPL-2.0、
  EPL-1.0/2.0、CDDL-1.0/1.1、CPL-1.0
- 强著佐权：GPL-1.0/2.0/3.0（`-only`/`-or-later`）
- 网络著佐权：AGPL-3.0（`-only`/`-or-later`）
- 例外：Classpath、GCC 2.0/3.1、Autoconf 2.0/3.0、Nokia-Qt、Linux-syscall-note、
  LLVM、Font-exception-2.0、OCaml-LGPL-linking-exception、
  Universal-FOSS-exception-1.0、Bootloader-exception
- 特殊原子：`NONE`、`NOASSERTION`、任意 `LicenseRef-*`（名称含
  Proprietary/Commercial 时按专有处理）

裸版本号（如 `GPL-2.0`）与 `+`（如 `GPL-2.0+`）会自动归一化为现代
`-only` / `-or-later` 标识。完整定义见 `app/catalog.py`。

---

## 配置项

配置通过环境变量提供，统一以 `AUDIT_` 为前缀；compose 中可直接修改
`environment`，或复制 `.env.example` 为 `.env`。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUDIT_HOST` | `0.0.0.0` | 监听地址 |
| `AUDIT_PORT` | `8000` | 监听端口（compose 端口映射同步为 `8000:8000`） |
| `AUDIT_STORE_CAPACITY` | `10000` | 幂等仓库最大条目数（LRU 淘汰），`0` 为不限 |
| `AUDIT_STORE_TTL_SECONDS` | `3600` | 幂等结果保留秒数 |
| `AUDIT_CORS_ALLOW_ORIGINS` | `*` | CORS 允许来源，逗号分隔 |

---

## 测试

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

共 54 个用例，覆盖 SPDX 解析（优先级/括号/归一化/错误位置）、全部主要兼容性
冲突场景、OR 双许可分支、链接例外、环与路径上限、幂等语义与 422/404 错误信封。

---

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用、异常处理、OpenAPI 元信息
│   ├── routes.py      # /api/v1/audits 等 HTTP 路由
│   ├── models.py      # Pydantic 请求/响应模型
│   ├── spdx.py        # SPDX 表达式解析器（AND/OR/WITH/括号/+）与 DNF 展开
│   ├── catalog.py     # 许可证/例外目录、版本解析、条款引用
│   ├── engine.py      # 审计引擎：路径传播、兼容性判定、替换建议
│   ├── service.py     # 审计编排 + audit_id
│   ├── store.py       # 幂等仓库（规范化哈希 + LRU + TTL）
│   └── config.py      # 环境变量配置
├── tests/             # pytest 测试（54 个用例）
├── examples/audit_request.json
├── Dockerfile
├── docker-compose.yml
├── requirements.txt / requirements-dev.txt
└── README.md
```
