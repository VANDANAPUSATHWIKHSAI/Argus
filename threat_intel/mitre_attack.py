"""MITRE ATT&CK STIX knowledge-base client."""

from datetime import datetime, timezone
from typing import Any, Optional

import requests


class MitreAttackClient:
    def __init__(self, bundle_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json", timeout: float = 10.0):
        self.bundle_url = bundle_url
        self.timeout = timeout
        self.last_updated: Optional[datetime] = None
        self.max_age_seconds = 604800.0
        self._objects: list[dict[str, Any]] = []

    def _load(self) -> None:
        response = requests.get(self.bundle_url, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        objects = payload.get("objects") if isinstance(payload, dict) else None
        if not isinstance(objects, list):
            raise ValueError("MITRE ATT&CK response does not contain objects")
        self._objects = [item for item in objects if isinstance(item, dict)]
        self.last_updated = datetime.now(timezone.utc)

    def get_technique(self, technique_id: str) -> dict[str, Any]:
        if not self._objects:
            self._load()
        target = technique_id.lower()
        for item in self._objects:
            if item.get("type") not in {"attack-pattern"}:
                continue
            if item.get("revoked") or item.get("x_mitre_deprecated"):
                continue
            external_refs = item.get("external_references", [])
            if any(str(ref.get("external_id", "")).lower() == target for ref in external_refs):
                return item
        return {}

    def get_tactics(self) -> list[dict[str, Any]]:
        if not self._objects:
            self._load()
        return [item for item in self._objects if item.get("type") == "x-mitre-tactic"]

    def build_killchain_graph(self) -> dict[str, Any]:
        if not self._objects:
            self._load()
        return {"objects": self._objects}
