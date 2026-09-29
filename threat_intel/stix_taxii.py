"""STIX/TAXII client used by Agent 5a.

The client is deliberately small and dependency-injected: callers can use a
mock in tests, while production can point it at a TAXII collection or a
local STIX bundle URL.
"""

from datetime import datetime, timezone
from typing import Any, Optional

import requests

from config.settings import settings


class StixTaxiiClient:
    def __init__(self, server_url: Optional[str] = None, api_key: Optional[str] = None, timeout: float = 10.0):
        self.server_url = server_url or settings.taxii_server_url
        self.api_key = api_key or settings.taxii_api_key
        self.timeout = timeout
        self.last_updated: Optional[datetime] = None
        self.max_age_seconds = 86400.0
        self._indicators: list[dict[str, Any]] = []

    def fetch_indicators(self, server_url: Optional[str] = None) -> list[dict[str, Any]]:
        url = server_url or self.server_url
        if not url:
            raise RuntimeError("TAXII server URL is not configured")
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        objects = payload.get("objects", payload.get("objects", payload)) if isinstance(payload, dict) else payload
        if not isinstance(objects, list):
            raise ValueError("STIX/TAXII response does not contain an object list")
        self._indicators = [item for item in objects if isinstance(item, dict)]
        self.last_updated = datetime.now(timezone.utc)
        return self._indicators

    def check_ioc(self, ioc: str) -> dict[str, Any]:
        if not self._indicators:
            self.fetch_indicators()
        normalized = ioc.lower()
        matches = []
        for indicator in self._indicators:
            pattern = str(indicator.get("pattern", "")).lower()
            name = str(indicator.get("name", "")).lower()
            description = str(indicator.get("description", "")).lower()
            if normalized in pattern or normalized in name or normalized in description:
                matches.append(indicator)
        return matches[0] if matches else {}
