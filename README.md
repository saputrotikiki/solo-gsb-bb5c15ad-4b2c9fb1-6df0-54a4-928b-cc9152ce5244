# 依赖许可兼容性审计 API

基于 **Python 3.12 + FastAPI** 实现的依赖许可证兼容性审计服务。输入组件清单、
依赖有向图和项目的 **SPDX 许可证表达式**，服务会：

1. 解析 SPDX 表达式中的 `AND` / `OR` / `WITH` 组合（含括号、`+` 后缀、
   `GPL-2.0` 旧式标识、`MIT/Apache-2.0` 双重许可写法）；
2. 把**项目发布许可证沿依赖路径向下传播**，对路径上每个组件求值；
3. 返回每条**冲突路径**（根 → … → 冲突组件的完整节点链与链接方式）、
   触发的**具体许可证条款**（如 `GPL-2.0 §2(b)`、`AGPL-3.0 §13`），
   以及清单中声明的**可选替换节点**及其兼容性评估；
4. 提供**幂等**审计接口（内容指纹 + 自定义幂等键）和自动生成的
   **OpenAPI / Swagger UI / ReDoc** 文档。

---

## 一、快速启动（Docker Compose，一键）

要求：已安装 Docker 与 Docker Compose（`docker compose` 子命令）。

```bash
docker compose up --build
```

服务启动后监听 **8000 端口**：

| 地址 | 说明 |
| --- | --- |
| <http://localhost:8000/docs> | Swagger UI（可在线调试） |
| <http://localhost:8000/redoc> | ReDoc 文档 |
| <http://localhost:8000/openapi.json> | OpenAPI 3.1 描述文件 |
| <http://localhost:8000/health> | 健康检查 |

后台运行 / 停止：

```bash
docker compose up --build -d
docker compose down
```

> 容器以非 root 用户运行，并内置了指向 `/health` 的 HEALTHCHECK。

---

## 二、本地开发启动（不使用 Docker）

要求 Python ≥ 3.11：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 方式 A：uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 方式 B：模块入口（APP_ENV=development 时自动热重载）
python -m app.main
```

运行测试：

```bash
pip install -r requirements-dev.txt
pytest -q
```

---

## 三、配置项

所有配置通过环境变量注入（见 `.env.example`，Compose 的 `environment` 段
展示了默认值）：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | 监听地址 |
| `PORT` | **`8000`** | 监听端口 |
| `APP_ENV` | `development` | `development` 下本地运行开启 uvicorn 热重载 |
| `LOG_LEVEL` | `info` | uvicorn 日志级别 |
| `MAX_PATHS_PER_NODE` | `1` | 每个冲突组件默认枚举的依赖路径条数（最短路径优先） |
| `HARD_MAX_PATHS` | `100` | 每组件路径条数的硬上限（请求参数 `max_paths_per_component` 的上界） |

> 请求体 `options.max_paths_per_component` 可在单次审计级别覆盖默认值（1–100）。

---

## 四、接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/v1/audits` | 提交清单执行审计（**幂等**） |
| `GET` | `/api/v1/audits/{audit_id}` | 获取历史审计快照 |
| `GET` | `/api/v1/audits` | 列出历史审计 |
| `GET` | `/api/v1/licenses` | 内置许可证规则与触发条款清单 |
| `GET` | `/health` | 健康检查 |

### 幂等语义

* **内容指纹**：`audit_id = SHA-256(规范化请求 JSON)`，同样的清单永远得到
  同一个 `audit_id`，重复提交响应中 `replayed=true`。
* **自定义幂等键**：请求头 `Idempotency-Key: <任意字符串>`。同键重放首次
  结果；同键但请求体不同返回 `409 idempotency_key_conflict`。

### 请求体结构

```jsonc
{
  "project_key": "root",              // 依赖图根节点 id
  "project_name": "my-saas-backend",
  "release_license": "AGPL-3.0-or-later", // 项目发布许可证 SPDX 表达式（沿路径传播）
  "components": [
    {
      "key": "pkg:npm/gpl-utils@0.9.0",   // 图中唯一 id（建议用 purl）
      "name": "gpl-utils",
      "version": "0.9.0",
      "license_expression": "GPL-2.0-only",
      // 该组件是某个冲突组件的可选替换节点：
      "replacement_for": "pkg:npm/gpl-utils@0.9.0",
      "replacement_label": "社区 MIT 分叉，API 兼容 0.9.x"
    }
  ],
  "edges": [
    {"source": "root", "target": "pkg:npm/gpl-utils@0.9.0", "link": "static"}
    // link: static（静态链接/打包） | dynamic（动态链接/独立进程调用）
  ],
  "options": {
    "max_paths_per_component": 5,   // 每组件最多返回的依赖路径
    "include_warnings": true,       // 是否返回可履行义务提示
    "audit_unreachable": true       // 是否审计图中不可达的孤立组件
  }
}
```

### 快速试一把

```bash
curl -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-1' \
  --data @examples/audit_request.json
```

也可直接在 <http://localhost:8000/docs> 中使用该示例。

### 响应中的核心字段

* `status`：`compliant` / `warnings_only` / `conflicts_found`；
* `findings[].severity`：`conflict`（无法以此许可证发布）或
  `warning`（可发布但须履行义务，如动态链接 LGPL 须保留替换能力并提供源码）；
* `findings[].paths[]`：每条**冲突路径**，含完整 `nodes` 链、该路径传播的
  `project_license_leaf` 与路径上的 `effective_link`（任一静态边即 `static`）；
* `findings[].triggering_terms[]`：触发判定的许可证叶子、人类可读原因、
  机器可读 `reason` 码与具体 `clause` 条款；
* `findings[].replacements[]`：清单里声明的**可选替换节点**及其兼容性结论。

---

## 五、审计模型说明

判定基于内置规则库 `app/licenses_db.py`（覆盖 MIT/Apache-2.0/BSD/MPL/LGPL/
EPL/CDDL/GPL/AGPL/SSPL/专有许可等），按 copyleft 强度与 GPL 家族兼容矩阵求值：

* **宽松 → 任意**：兼容；特例是 `Apache-2.0` 的专利终止条款与
  `GPL-2.0-only` 不兼容（`GPL-2.0-or-later` 升级到 GPLv3 后兼容）。
* **弱 copyleft（LGPL/MPL/EPL）**：进入 MIT/专有项目为冲突；进入兼容的
  GPL/AGPL 项目为 `warning`，静态链接额外提示重新链接义务。
* **强 copyleft（GPL）**：只能随兼容的 GPL 家族发布；`GPL-2.0-only`
  不可升级到 GPL-3.0，`-or-later` 可以；GPLv3 组件允许单向并入 AGPLv3 作品。
* **网络 copyleft（AGPL/SSPL）**：触发 `§13` 网络交互源码提供义务，
  项目必须以兼容的网络 copyleft 许可证发布。
* **WITH 例外**：`Classpath-exception-2.0`、`GCC-exception-*`、
  `LGPL-3.0-linking-exception` 等链接例外会把 GPL 的作品级 copyleft
  **降级为弱 copyleft** 再参与判定。
* **表达式语义**：`OR` = 择一许可（任一分支兼容即可，冲突分支不再上报）；
  `AND` = 必须同时满足（任一分支冲突即冲突）。
* 未识别的 SPDX id（`LicenseRef-*` 或拼写错误）按冲突上报并标注
  `unknown-license`，需人工复核。

这是一套可读、可扩展的**简化法律模型**，用于工程侧门禁与风险定位，
不构成法律意见；正式发布前请由法务复核。

---

## 六、项目结构

```
.
├── app/
│   ├── main.py          # FastAPI 入口、路由、幂等接口、OpenAPI 元信息
│   ├── schemas.py       # 请求/响应 Pydantic 模型（OpenAPI 文档来源）
│   ├── spdx.py          # SPDX 表达式词法/递归下降解析器（AND/OR/WITH）
│   ├── licenses_db.py   # 许可证规则库：copyleft 等级、GPL 兼容矩阵、条款
│   ├── audit.py         # 兼容性引擎：两两判定、表达式求值、依赖路径传播
│   ├── service.py       # 审计编排：解析 → 建图 → 路径传播 → 报告
│   ├── store.py         # 进程内幂等存储（可替换为 Redis/DB 实现）
│   └── config.py        # 环境变量配置
├── examples/audit_request.json
├── tests/               # 58 个 pytest 用例（解析器/引擎/编排/HTTP）
├── Dockerfile           # python:3.12-slim，非 root，HEALTHCHECK
├── docker-compose.yml   # 一键启动，映射 8000:8000
├── requirements.txt
└── requirements-dev.txt
```
