"""STIX/TAXII client used by Agent 5a."""

from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import ipaddress
import re

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
        normalized = self._normalize_ioc(ioc)
        observable_types = self._observable_types(ioc)
        for indicator in self._indicators:
            if self._pattern_matches(indicator.get("pattern"), normalized, observable_types):
                return indicator
        return {}

    @staticmethod
    def _normalize_ioc(value: str) -> str:
        value = value.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        if value.lower().startswith(("http://", "https://")):
            parsed = urlsplit(value)
            if not parsed.hostname:
                return value.lower()
            host = parsed.hostname.rstrip(".").lower()
            port = parsed.port
            netloc = host
            if port and not ((parsed.scheme.lower() == "http" and port == 80) or
                             (parsed.scheme.lower() == "https" and port == 443)):
                netloc = f"{host}:{port}"
            query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
            return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
        return value.rstrip(".").lower()

    @staticmethod
    def _observable_types(value: str) -> set[tuple[str, str]]:
        value = value.strip()
        try:
            ip = ipaddress.ip_address(value)
            return {("ipv4-addr" if ip.version == 4 else "ipv6-addr", "value")}
        except ValueError:
            pass
        if value.lower().startswith(("http://", "https://")):
            return {("url", "value")}
        if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
            return {("file", "hashes")}
        if re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?", value):
            return {("domain-name", "value")}
        if re.search(r"\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|docm?|xlsm?|zip|rar|elf)$", value, re.IGNORECASE):
            return {("file", "name")}
        return set()

    @classmethod
    def _pattern_matches(
        cls,
        pattern: Any,
        normalized_ioc: str,
        observable_types: set[tuple[str, str]] | None = None,
    ) -> bool:
        if not isinstance(pattern, str):
            return False
        expression = pattern.strip()
        normalized_ioc = cls._normalize_ioc(normalized_ioc)
        if not expression or expression.count("[") != expression.count("]"):
            return False
        if expression.startswith("(") or expression.endswith(")"):
            return False
        clause_re = re.compile(
            r"\[\s*([a-z0-9-]+):(value|name|hashes\.[\"']?[^\"'\s=]+[\"']?)\s*=\s*(['\"])(.*?)\3\s*\]",
            re.IGNORECASE | re.DOTALL,
        )
        pos = 0
        clauses = []
        operators = []
        while True:
            while pos < len(expression) and expression[pos].isspace():
                pos += 1
            match = clause_re.match(expression, pos)
            if match is None:
                return False
            clauses.append((match.group(1), match.group(2), match.group(4)))
            pos = match.end()
            while pos < len(expression) and expression[pos].isspace():
                pos += 1
            if pos == len(expression):
                break
            operator = re.match(r"(AND|OR|NOT)\b", expression[pos:], re.IGNORECASE)
            if operator is None:
                return False
            operators.append(operator.group(1).upper())
            pos += operator.end()
            if operators[-1] == "NOT":
                return False
        if len(clauses) == 1 and not operators:
            return cls._single_pattern_matches(clauses[0], normalized_ioc, observable_types)
        if len(clauses) != len(operators) + 1:
            return False
        results = [
            cls._single_pattern_matches(clause, normalized_ioc, observable_types)
            for clause in clauses
        ]
        if all(item == "AND" for item in operators):
            return all(results)
        if all(item == "OR" for item in operators):
            return any(results)
        return False

    @classmethod
    def _single_pattern_matches(
        cls,
        clause: tuple[str, str],
        normalized_ioc: str,
        observable_types: set[tuple[str, str]] | None,
    ) -> bool:
        object_type, property_expression, literal = clause
        object_type = object_type.lower()
        property_name = (
            "hashes" if property_expression.lower().startswith("hashes.")
            else property_expression.lower()
        )
        if observable_types is None or (object_type, property_name) not in observable_types:
            return False
        return cls._normalize_ioc(literal) == normalized_ioc
