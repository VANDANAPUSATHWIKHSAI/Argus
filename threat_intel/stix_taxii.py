"""STIX/TAXII client used by Agent 5a."""

from datetime import datetime, timezone
from typing import Any, Optional

from config.settings import settings


class StixTaxiiClient:
    def __init__(
        self,
        server_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.server_url = server_url or settings.taxii_server_url
        self.api_key = api_key or settings.taxii_api_key
        self.timeout = timeout
        self.last_updated: Optional[datetime] = None
        self.max_age_seconds = 86400.0
        self._indicators: list[dict[str, Any]] = []

    def fetch_indicators(self, server_url: Optional[str] = None) -> list[dict[str, Any]]:
        """Fetch STIX objects from a TAXII 2.1 discovery or collection URL."""
        url = server_url or self.server_url
        if not url:
            raise RuntimeError("TAXII server URL is not configured")
        objects = self._fetch_taxii_objects(url)
        if not isinstance(objects, list):
            raise ValueError("STIX/TAXII response does not contain an object list")
        self._indicators = [item for item in objects if isinstance(item, dict)]
        self.last_updated = datetime.now(timezone.utc)
        return self._indicators

    def _fetch_taxii_objects(self, url: str) -> list[dict[str, Any]]:
        try:
            from taxii2client.v21 import Collection, Server
        except ImportError as exc:
            raise RuntimeError("taxii2-client is required for TAXII feeds") from exc

        if "/collections/" in url.rstrip("/"):
            collection = Collection(url, verify=True)
            bundle = collection.get_objects()
            return bundle.get("objects", []) if isinstance(bundle, dict) else []

        if self.api_key:
            import requests

            response = requests.get(
                url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("objects", payload) if isinstance(payload, dict) else payload

        server = Server(url, verify=True)
        for api_root in server.api_roots:
            for collection in api_root.collections:
                if getattr(collection, "can_read", True):
                    bundle = collection.get_objects()
                    return bundle.get("objects", []) if isinstance(bundle, dict) else []
        raise RuntimeError("TAXII server has no readable collections")

    def check_ioc(self, ioc: str) -> dict[str, Any]:
        if not self._indicators:
            self.fetch_indicators()
        normalized = ioc.lower()
        for indicator in self._indicators:
            text = " ".join(
                str(indicator.get(field, "")).lower()
                for field in ("pattern", "name", "description")
            )
            if normalized in text:
                return indicator
        return {}
