"""内存幂等存储。

提供两层幂等保证：

1. Idempotency-Key（客户端提供）：同一 key 重放同一结果；
   key 相同但载荷不同 -> 409。
2. 内容指纹（audit_id = sha256(规范化请求)）：相同清单天然得到
   相同 id 与结果，无需客户端配合。

存储为进程内字典，水平扩容时应替换为 Redis/数据库实现，
接口刻意保持最小（get/put/list）。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .schemas import AuditResponse


@dataclass
class StoredAudit:
    response: AuditResponse
    fingerprint: str
    idempotency_key: str | None
    created_at: str


class IdempotentStore:
    def __init__(self, max_records: int = 10_000) -> None:
        self._by_id: dict[str, StoredAudit] = {}
        self._by_key: dict[str, str] = {}
        self._lock = threading.Lock()
        self._max = max_records

    def get_by_id(self, audit_id: str) -> StoredAudit | None:
        with self._lock:
            return self._by_id.get(audit_id)

    def get_by_key(self, key: str) -> StoredAudit | None:
        with self._lock:
            audit_id = self._by_key.get(key)
            return self._by_id.get(audit_id) if audit_id else None

    def put(self, key: str | None, fingerprint: str, response: AuditResponse,
            created_at: str) -> tuple[StoredAudit, bool]:
        """写入审计结果，返回(记录, 是否为重放)。相同指纹直接返回历史快照。"""
        with self._lock:
            existing = self._by_id.get(fingerprint)
            if existing:
                if key and key not in self._by_key:
                    self._by_key[key] = fingerprint
                return existing, True

            if key:
                other_id = self._by_key.get(key)
                if other_id and other_id != fingerprint:
                    raise KeyInUse(key)
                self._by_key[key] = fingerprint

            record = StoredAudit(
                response=response, fingerprint=fingerprint,
                idempotency_key=key, created_at=created_at,
            )
            self._by_id[fingerprint] = record
            if len(self._by_id) > self._max:  # 简单淘汰最早记录
                oldest = next(iter(self._by_id))
                old = self._by_id.pop(oldest)
                if old.idempotency_key:
                    self._by_key.pop(old.idempotency_key, None)
            return record, False

    def list_all(self) -> list[StoredAudit]:
        with self._lock:
            return sorted(self._by_id.values(), key=lambda r: r.created_at,
                          reverse=True)


class KeyInUse(Exception):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Idempotency-Key {key!r} 已绑定不同的审计请求")
