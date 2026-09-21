"""应用配置（环境变量前缀 AUDIT_）。"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUDIT_", env_file=".env", extra="ignore"
    )

    app_name: str = "依赖许可兼容性审计 API"
    version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8000
    # 内存幂等仓库的最大条目数（防止无界增长）；0 表示不限制。
    store_capacity: int = 10_000
    store_ttl_seconds: int = 3600
    cors_allow_origins: str = "*"


@lru_cache
def get_settings() -> Settings:
    return Settings()
