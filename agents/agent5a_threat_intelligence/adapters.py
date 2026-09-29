from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol


class StixAdapter(Protocol):
    def check_ioc(self, ioc: str) -> Any: ...


class MitreAdapter(Protocol):
    def get_technique(self, technique_id: str) -> Any: ...


class VulnerabilityAdapter(Protocol):
    def lookup_cve(self, cve_id: str) -> Any: ...

    def get_cisa_kev(self) -> Any: ...


def adapter_timestamp(adapter: Any) -> datetime | None:
    value = getattr(adapter, "last_updated", None) or getattr(adapter, "fetched_at", None)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def adapter_max_age(adapter: Any) -> float | None:
    value = getattr(adapter, "max_age_seconds", None)
    return float(value) if value is not None else None
