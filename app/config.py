from __future__ import annotations

import os


class Settings:
    """运行期配置，全部可通过环境变量覆盖（容器部署时注入）。"""

    app_name: str = os.getenv("APP_NAME", "license-audit-api")
    app_env: str = os.getenv("APP_ENV", "development")
    log_level: str = os.getenv("LOG_LEVEL", "info")
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    # 单个组件默认枚举的依赖路径条数（1 = 只返回最短路径）
    default_max_paths: int = int(os.getenv("MAX_PATHS_PER_NODE", "1"))
    # 防止恶意清单导致路径爆炸的硬上限
    hard_max_paths: int = int(os.getenv("HARD_MAX_PATHS", "100"))


settings = Settings()
