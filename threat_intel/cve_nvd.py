"""NVD CVE and CISA KEV clients."""

from datetime import datetime, timezone
from typing import Any, Optional

import requests

from config.settings import settings


class CVEClient:
    def __init__(self, nvd_api_key: Optional[str] = None, kev_url: Optional[str] = None, timeout: float = 10.0):
        self.nvd_api_key = nvd_api_key or settings.nvd_api_key
        self.kev_url = kev_url or settings.cisa_kev_url
        self.timeout = timeout
        self.last_updated: Optional[datetime] = None
        self.max_age_seconds = 86400.0
        self._kev: Optional[list[dict[str, Any]]] = None

    def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not vulnerabilities:
            return {}
        cve = vulnerabilities[0].get("cve", {})
        self.last_updated = datetime.now(timezone.utc)
        return {
            "id": cve_id,
            "description": next(
                (item["value"] for item in cve.get("descriptions", []) if item.get("lang") == "en"),
                None,
            ),
            "source": cve.get("sourceIdentifier"),
            "raw": cve,
        }

    def search_by_product(self, product: str) -> list[dict[str, Any]]:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": product},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json().get("vulnerabilities", [])

    def get_cisa_kev(self) -> list[dict[str, Any]]:
        response = requests.get(self.kev_url, timeout=self.timeout)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("CISA KEV response does not contain vulnerabilities")
        self._kev = vulnerabilities
        self.last_updated = datetime.now(timezone.utc)
        return vulnerabilities
