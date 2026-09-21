"""审计服务层：调用引擎、封装幂等仓库。"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from .engine import run_audit
from .models import AuditRequest
from .store import AuditStore, canonical_hash


class AuditService:
    def __init__(self, store: Optional[AuditStore] = None):
        self.store = store or AuditStore()

    def submit(self, req: AuditRequest,
               idempotency_key: Optional[str] = None,
               persist: bool = True) -> tuple[dict, bool]:
        payload = req.model_dump(mode="json", by_alias=True)
        content_hash = canonical_hash(payload)
        key = idempotency_key or content_hash

        if persist:
            cached = self.store.get(key)
            if cached is not None:
                return {**cached, "created": False}, False

        result = run_audit(req)
        audit_id = hashlib.sha256((content_hash + "|audit").encode()).hexdigest()[
            :16
        ]
        envelope = {
            "audit_id": audit_id,
            "idempotency_key": key,
            "project": payload["project"],
            "created": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": result["status"],
            "summary": result["summary"],
            "findings": result["findings"],
            "request": payload,
        }
        if not persist:
            return envelope, True
        stored, _created = self.store.put_if_absent(key, envelope)
        return {**stored, "created": _created}, _created

    def get(self, audit_id: str) -> Optional[dict]:
        # 当前进程内仓库以幂等键存储；按 audit_id 线性扫描（容量受控）。
        for item in self.store._data.values():  # noqa: SLF001
            result = item["result"]
            if result["audit_id"] == audit_id:
                return result
        return None


service_singleton: Optional[AuditService] = None


def get_service() -> AuditService:
    global service_singleton
    if service_singleton is None:
        from .config import get_settings

        settings = get_settings()
        service_singleton = AuditService(
            AuditStore(
                capacity=settings.store_capacity,
                ttl_seconds=settings.store_ttl_seconds,
            )
        )
    return service_singleton
