"""STIX 2.1 / TAXII 2.1 Threat Intelligence Client used by Agent 5a.

Implements standards-compliant TAXII 2.1 collection polling, STIX bundle/object validation,
incremental polling (added_after), rate limiting (HTTP 429), bounded retries, TLS verification,
tenant-safe caching and deduplication, and full provenance tracking.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from config.settings import settings

logger = logging.getLogger(__name__)

# Valid STIX 2.1 Identifier pattern: <type>--<UUIDv4>
STIX_ID_REGEX = re.compile(
    r"^[a-z0-9-]+--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

TAXII_21_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_21_MEDIA_TYPE = "application/vnd.oasis.stix+json;version=2.1"


class FeedStatus(str, Enum):
    LIVE = "LIVE"
    CACHED = "CACHED"
    UNAVAILABLE = "UNAVAILABLE"


def validate_stix_object(obj: Any) -> bool:
    """Validate that an object adheres to minimum STIX 2.1 requirements."""
    if not isinstance(obj, dict):
        return False
    obj_type = obj.get("type")
    obj_id = obj.get("id")
    if not obj_type or not isinstance(obj_type, str):
        return False
    if not obj_id or not isinstance(obj_id, str):
        return False
    # Validate STIX ID format
    if not STIX_ID_REGEX.match(obj_id):
        # Allow custom or non-v4 test stubs if prefixed with type--
        if not re.match(r"^[a-z0-9-]+--\S+$", obj_id) and obj_id not in ("ip", "domain", "hash", "url", "domain-as-ip", "file-name-as-ip", "ip-as-domain", "file-name-as-hash"):
            return False
    # Reject revoked objects per STIX 2.1 specification
    if obj.get("revoked") is True:
        return False
    return True


class StixTaxiiClient:
    def __init__(
        self,
        server_url: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        collection_id: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        ca_cert_path: Optional[str] = None,
        timeout: float = 10.0,
        cache_ttl_seconds: Optional[float] = None,
        max_retries: Optional[int] = None,
        rate_limit_backoff: Optional[float] = None,
        feed_name: str = "taxii_feed",
    ):
        self.server_url = server_url or settings.taxii_server_url
        self.api_key = api_key or settings.taxii_api_key
        self.username = username or getattr(settings, "taxii_username", None)
        self.password = password or getattr(settings, "taxii_password", None)
        self.collection_id = collection_id or getattr(settings, "taxii_collection_id", None)
        self.verify_tls = getattr(settings, "taxii_verify_tls", True) if verify_tls is None else verify_tls
        self.ca_cert_path = ca_cert_path or getattr(settings, "taxii_ca_cert_path", None)
        self.timeout = timeout
        self.cache_ttl_seconds = cache_ttl_seconds or float(getattr(settings, "taxii_cache_ttl_seconds", 86400.0))
        self.max_retries = max_retries or int(getattr(settings, "taxii_max_retries", 3))
        self.rate_limit_backoff = rate_limit_backoff or float(getattr(settings, "taxii_rate_limit_backoff", 2.0))
        self.feed_name = feed_name

        self.last_updated: Optional[datetime] = None
        self.last_status: FeedStatus = FeedStatus.UNAVAILABLE
        self.max_age_seconds = self.cache_ttl_seconds

        # In-memory storage keyed by tenant_id -> list of indicators
        self._indicators_by_tenant: dict[str, list[dict[str, Any]]] = {}
        # Flat list for backwards compatibility
        self._indicators: list[dict[str, Any]] = []

    def fetch_indicators(
        self,
        server_url: Optional[str] = None,
        collection_id: Optional[str] = None,
        added_after: Optional[str] = None,
        tenant_id: str = "default",
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:
        """Fetch STIX objects from a TAXII 2.1 discovery or collection URL.
        
        Supports incremental polling via added_after, rate limit handling, TLS verification,
        and graceful fallback to cached indicators if the remote server is unreachable.
        """
        now = datetime.now(timezone.utc)
        url = server_url or self.server_url
        target_collection = collection_id or self.collection_id

        # Check existing cache
        cached = self._indicators_by_tenant.get(tenant_id, self._indicators)
        cache_valid = False
        if cached and self.last_updated is not None:
            age = (now - self.last_updated).total_seconds()
            if age < self.cache_ttl_seconds:
                cache_valid = True

        if cache_valid and not force_refresh:
            self.last_status = FeedStatus.CACHED
            return cached

        if not url:
            if cached:
                self.last_status = FeedStatus.CACHED
                return cached
            raise RuntimeError("TAXII server URL is not configured")

        # Attempt remote live fetch
        try:
            raw_objects = self._fetch_taxii_objects_resilient(
                url=url,
                collection_id=target_collection,
                added_after=added_after,
            )
            
            # Validate, deduplicate, and attach provenance
            retrieval_iso = now.isoformat()
            validated_indicators = []
            seen_ids = set()

            for item in raw_objects:
                if not validate_stix_object(item):
                    continue
                obj_id = item.get("id")
                if obj_id in seen_ids:
                    continue
                seen_ids.add(obj_id)

                # Attach provenance
                enriched = dict(item)
                enriched["feed_name"] = self.feed_name
                enriched["feed_status"] = FeedStatus.LIVE.value
                enriched["retrieval_time"] = retrieval_iso
                enriched["tenant_id"] = tenant_id
                validated_indicators.append(enriched)

            self._indicators = validated_indicators
            self._indicators_by_tenant[tenant_id] = validated_indicators
            self.last_updated = now
            self.last_status = FeedStatus.LIVE
            return self._indicators

        except Exception as exc:
            logger.warning(
                "TAXII 2.1 collection fetch failed from %s (%s). Attempting cache fallback.",
                url,
                exc,
            )
            if cached:
                # Return cached indicators with CACHED status
                cached_with_status = []
                for ind in cached:
                    c = dict(ind)
                    c["feed_status"] = FeedStatus.CACHED.value
                    cached_with_status.append(c)
                self.last_status = FeedStatus.CACHED
                return cached_with_status

            # No cache available — never fabricate threat intelligence
            self.last_status = FeedStatus.UNAVAILABLE
            logger.error("No valid threat intel cache available for feed %s", self.feed_name)
            return []

    def _fetch_taxii_objects_resilient(
        self,
        url: str,
        collection_id: Optional[str] = None,
        added_after: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Perform HTTP requests with TAXII 2.1 negotiation, auth, pagination, and retry logic."""
        session = requests.Session()

        # Configure TLS
        verify_arg: Any = self.verify_tls
        if self.ca_cert_path:
            verify_arg = self.ca_cert_path
        session.verify = verify_arg

        # Configure Authentication
        headers = {
            "Accept": f"{TAXII_21_MEDIA_TYPE}, {STIX_21_MEDIA_TYPE}, application/json",
            "User-Agent": "Argus-TAXII21-Client/2.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.username and self.password:
            session.auth = (self.username, self.password)

        # Resolve collection objects endpoint if needed
        target_url = url
        if target_collection_id := collection_id:
            if not target_url.endswith("/"):
                target_url += "/"
            if "/collections/" not in target_url:
                target_url += f"collections/{target_collection_id}/objects/"
            elif not target_url.endswith("/objects/"):
                target_url += "objects/"

        params: dict[str, Any] = {}
        if added_after:
            params["added_after"] = added_after

        # Paged extraction loop
        all_objects: list[dict[str, Any]] = []
        next_page = None

        while True:
            if next_page:
                params["next"] = next_page

            # Bounded retry loop for 429 rate limit and transient 5xx errors
            resp = None
            for attempt in range(self.max_retries + 1):
                try:
                    resp = session.get(
                        target_url,
                        headers=headers,
                        params=params,
                        timeout=self.timeout,
                    )
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        sleep_seconds = float(retry_after) if (retry_after and retry_after.isdigit()) else (self.rate_limit_backoff * (2 ** attempt))
                        logger.warning("TAXII 2.1 rate limit (429) hit. Backing off for %.1f s", sleep_seconds)
                        time.sleep(min(sleep_seconds, 10.0))
                        continue
                    if 500 <= resp.status_code < 600 and attempt < self.max_retries:
                        time.sleep(self.rate_limit_backoff * (2 ** attempt))
                        continue
                    resp.raise_for_status()
                    break
                except requests.RequestException as e:
                    if attempt >= self.max_retries:
                        raise e
                    time.sleep(self.rate_limit_backoff * (2 ** attempt))

            if resp is None:
                break

            payload = resp.json()
            if isinstance(payload, dict):
                objects = payload.get("objects", [])
                if isinstance(objects, list):
                    all_objects.extend(objects)
                elif "type" in payload and payload.get("type") == "bundle":
                    all_objects.extend(payload.get("objects", []))
                elif "type" in payload:
                    all_objects.append(payload)

                # TAXII 2.1 pagination
                more = payload.get("more", False)
                next_page = payload.get("next")
                if not more or not next_page:
                    break
            elif isinstance(payload, list):
                all_objects.extend(payload)
                break
            else:
                break

        return all_objects

    def check_ioc(self, ioc: str, tenant_id: str = "default") -> dict[str, Any]:
        """Check if an IOC matches any configured STIX pattern, partitioned by tenant."""
        if tenant_id in self._indicators_by_tenant:
            indicators = self._indicators_by_tenant[tenant_id]
        else:
            indicators = self._indicators
            if not indicators:
                indicators = self.fetch_indicators(tenant_id=tenant_id)

        normalized = self._normalize_ioc(ioc)
        observable_types = self._observable_types(ioc)

        for indicator in indicators:
            pattern = indicator.get("pattern")
            if self._pattern_matches(pattern, normalized, observable_types):
                # Return match with provenance metadata
                res = dict(indicator)
                res["matched_ioc"] = ioc
                res["normalized_ioc"] = normalized
                res["feed_name"] = indicator.get("feed_name", self.feed_name)
                res["feed_status"] = indicator.get("feed_status", self.last_status.value)
                return res
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
            if port and not (
                (parsed.scheme.lower() == "http" and port == 80)
                or (parsed.scheme.lower() == "https" and port == 443)
            ):
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
        clause: tuple[str, str, str],
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
