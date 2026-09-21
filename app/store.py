"""幂等审计结果仓库（进程内，线程安全，带容量上限与 TTL）。

以请求体规范化 JSON 的 SHA-256 作为幂等键；同一内容重复提交返回缓存结果。
生产环境多副本部署时可将本仓库替换为 Redis/数据库实现，接口保持不变。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Optional


def canonical_hash(request_json: bytes | dict) -> str:
    if isinstance(request_json, dict):
        blob = json.dumps(
            request_json, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    else:
        # 已经序列化：先解析再规范化，消除键序/空白差异。
        blob = json.dumps(
            json.loads(request_json), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class AuditStore:
    def __init__(self, capacity: int = 10_000, ttl_seconds: int = 3600):
        self._capacity = capacity
        self._ttl = ttl_seconds
        self._data: "OrderedDict[str, dict]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            if self._ttl and time.time() - item["stored_at"] > self._ttl:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return item["result"]

    def put_if_absent(self, key: str, result: dict) -> tuple[dict, bool]:
        """返回 (result, created)。已存在时返回旧结果。"""
        with self._lock:
            existing = self._data.get(key)
            if existing is not None and not (
                self._ttl and time.time() - existing["stored_at"] > self._ttl
            ):
                self._data.move_to_end(key)
                return existing["result"], False
            self._data[key] = {"stored_at": time.time(), "result": result}
            if self._capacity and len(self._data) > self._capacity:
                self._data.popitem(last=False)
            return result, True

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
