from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from typing import Any, Iterable

from agents.base_agent import BaseAgent
from agents.agent5a_threat_intelligence.adapters import adapter_max_age, adapter_timestamp
from agents.agent5a_threat_intelligence.schemas import (
    Agent5aInput,
    Agent5aOutput,
    ExecutionStatus,
    FeedState,
    FeedStatus,
    Indicator,
    IndicatorType,
    Provenance,
    SanitizationSummary,
    ThreatMatch,
    ValidationResult,
)

_HASH_RE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Za-z0-9])")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>'\"`\])}]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
_FILENAME_RE = re.compile(r"(?<![\w/\\])[\w .-]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|docm?|xlsm?|zip|rar|elf)\b", re.IGNORECASE)


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _text_fields(item: Any) -> Iterable[str]:
    if isinstance(item, dict):
        values = item.values()
    elif hasattr(item, "model_dump"):
        values = item.model_dump().values()
    else:
        values = vars(item).values() if hasattr(item, "__dict__") else [item]
    for value in values:
        if isinstance(value, str):
            yield value


def _normalize_indicator(value: str, kind: IndicatorType) -> str:
    value = value.strip().rstrip(".,;:)]}")
    if kind in {IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.CVE, IndicatorType.MITRE_TECHNIQUE}:
        return value.lower()
    if kind == IndicatorType.FILE_HASH:
        return value.lower()
    return value


def extract_indicators(findings: list[Any]) -> list[Indicator]:
    found: dict[tuple[IndicatorType, str], set[str]] = {}
    for finding in findings:
        finding_id = str(_value(finding, "finding_id", _value(finding, "id", "")))
        text = "\n".join(_text_fields(finding))
        candidates: list[tuple[IndicatorType, str]] = []
        candidates.extend((IndicatorType.URL, x) for x in _URL_RE.findall(text))
        candidates.extend((IndicatorType.FILE_HASH, x) for x in _HASH_RE.findall(text))
        candidates.extend((IndicatorType.CVE, x) for x in _CVE_RE.findall(text))
        candidates.extend((IndicatorType.MITRE_TECHNIQUE, x) for x in _MITRE_RE.findall(text))
        candidates.extend((IndicatorType.DOMAIN, x) for x in _DOMAIN_RE.findall(text))
        candidates.extend((IndicatorType.FILE_NAME, x) for x in _FILENAME_RE.findall(text))
        for raw in text.split():
            token = raw.strip(".,;:()[]{}<>\"'")
            try:
                ipaddress.ip_address(token)
                candidates.append((IndicatorType.IP, token))
            except ValueError:
                pass
        for kind, raw in candidates:
            normalized = _normalize_indicator(raw, kind)
            if kind == IndicatorType.DOMAIN and normalized.startswith(("http://", "https://")):
                continue
            found.setdefault((kind, normalized), set()).add(finding_id)
    return [
        Indicator(value=normalized, normalized_value=normalized, indicator_type=kind, finding_ids=sorted(ids))
        for (kind, normalized), ids in sorted(found.items(), key=lambda pair: (pair[0][0].value, pair[0][1]))
        if normalized
    ]


class ThreatIntelligenceAgent(BaseAgent):
    timeout_seconds = 10.0

    def run(self, case_id: str, context: dict) -> dict:
        input_data = Agent5aInput(
            case_id=case_id,
            tenant_id=context.get("tenant_id", self.tenant_id or "default"),
            fir_findings=self._findings(context.get("fir_findings", [])),
            agent2_output=self._as_dict(context.get("agent2_output", {})),
        )
        indicators = extract_indicators(input_data.fir_findings)
        statuses: list[FeedStatus] = []
        matches: list[ThreatMatch] = []
        errors: list[str] = []
        sanitization = SanitizationSummary()

        feeds = [
            ("stix_taxii", context.get("stix_client"), [i for i in indicators if i.indicator_type in {
                IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.FILE_HASH, IndicatorType.FILE_NAME
            }], "check_ioc"),
            ("mitre_attack", context.get("mitre_client"), [i for i in indicators if i.indicator_type == IndicatorType.MITRE_TECHNIQUE], "get_technique"),
            ("nvd_cve", context.get("cve_client"), [i for i in indicators if i.indicator_type == IndicatorType.CVE], "lookup_cve"),
        ]
        for feed_name, adapter, feed_indicators, method_name in feeds:
            feed_matches, status, feed_errors, sanitized_count, blocked_count = self._query_feed(
                feed_name, adapter, feed_indicators, method_name, input_data
            )
            matches.extend(feed_matches)
            statuses.append(status)
            errors.extend(feed_errors)
            sanitization.fields_sanitized += sanitized_count
            sanitization.blocked_fields += blocked_count

        kev_matches, kev_status, kev_errors = self._query_kev(context.get("cve_client"), indicators, input_data)
        matches.extend(kev_matches)
        statuses.append(kev_status)
        errors.extend(kev_errors)

        evidence_ids = sorted({fid for indicator in indicators for fid in indicator.finding_ids if fid})
        valid_matches = [match for match in matches if match.validation.citation_valid and match.validation.provenance_valid]
        validation_flags = [
            f"invalid_match:{match.source}:{match.indicator.normalized_value}"
            for match in matches if not match.validation.citation_valid or not match.validation.provenance_valid
        ]
        failed_feeds = [s for s in statuses if s.state not in {FeedState.HEALTHY, FeedState.NO_MATCH}]
        if not indicators and not errors:
            status = ExecutionStatus.SUCCESS
        elif valid_matches or (indicators and not failed_feeds):
            status = ExecutionStatus.PARTIAL_SUCCESS if failed_feeds or validation_flags else ExecutionStatus.SUCCESS
        else:
            status = ExecutionStatus.FAILED
        output = Agent5aOutput(
            case_id=input_data.case_id,
            tenant_id=input_data.tenant_id,
            indicators=indicators,
            ioc_matches=[m for m in valid_matches if m.source == "stix_taxii"],
            mitre_mappings=[m for m in valid_matches if m.source == "mitre_attack"],
            vulnerability_matches=[m for m in valid_matches if m.source == "nvd_cve"],
            cisa_kev_results=[m for m in valid_matches if m.source == "cisa_kev"],
            feed_status=statuses,
            provenance=[m.provenance for m in valid_matches],
            sanitization_summary=sanitization,
            validation_flags=validation_flags,
            execution_status=status,
            error_details=errors,
            agent2_context=input_data.agent2_output,
            model_used=getattr(self.model, "model_name", None),
            reasoning_summary=self._reason_about_enrichment(
                indicators, valid_matches, input_data.agent2_output
            ),
            claim=f"Threat-intelligence enrichment completed with status {status.value}; {len(valid_matches)} validated matches.",
            evidence_ids=evidence_ids,
        )
        return output.model_dump(mode="json")

    def _reason_about_enrichment(
        self, indicators: list[Indicator], matches: list[ThreatMatch], agent2_output: dict
    ) -> str | None:
        """Ask Qwen for bounded narration; deterministic matches remain authoritative."""
        if self.model is None or not hasattr(self.model, "generate") or not matches:
            return None
        prompt = (
            "Summarize the following threat-intelligence enrichment for an analyst. "
            "Do not claim that an external match proves current-case activity. "
            "Do not invent indicators, evidence IDs, or relationships. "
            "Mention that FIR findings are authoritative current-case evidence.\n"
            f"Indicators: {[i.model_dump() for i in indicators]}\n"
            f"Validated external matches: {[m.model_dump() for m in matches]}\n"
            f"Agent 2 correlation context: {agent2_output}\n"
        )
        try:
            return str(self.model.generate(prompt))
        except Exception as exc:
            return f"Model reasoning unavailable: {type(exc).__name__}: {exc}"

    def _query_feed(self, name: str, adapter: Any, indicators: list[Indicator], method_name: str, data: Agent5aInput):
        if not indicators:
            return [], FeedStatus(feed=name, state=FeedState.NO_MATCH), [], 0, 0
        if adapter is None:
            return [], FeedStatus(feed=name, state=FeedState.UNAVAILABLE, error="adapter not configured"), [f"{name}: adapter not configured"], 0, 0
        method = getattr(adapter, method_name, None)
        if not callable(method):
            return [], FeedStatus(feed=name, state=FeedState.UNAVAILABLE, error=f"missing {method_name}"), [f"{name}: missing {method_name}"], 0, 0
        results: list[ThreatMatch] = []
        errors: list[str] = []
        sanitized_count = blocked_count = 0
        for indicator in indicators:
            try:
                raw = self._call_with_timeout(method, indicator.normalized_value)
                if raw is None or raw == {} or raw == []:
                    continue
                if not isinstance(raw, (dict, list)):
                    raise TypeError("adapter response must be a mapping or list")
                candidates = raw if isinstance(raw, list) else [raw]
                for candidate in candidates:
                    if not isinstance(candidate, dict):
                        raise TypeError("adapter result entries must be mappings")
                    match, was_sanitized, was_blocked = self._match(name, indicator, candidate, data)
                    results.append(match)
                    sanitized_count += was_sanitized
                    blocked_count += was_blocked
            except FuturesTimeoutError:
                errors.append(f"{name}: timeout for {indicator.normalized_value}")
            except Exception as exc:
                errors.append(f"{name}: {type(exc).__name__}: {exc}")
        status = self._status(name, adapter, len(results), errors)
        return results, status, errors, sanitized_count, blocked_count

    def _query_kev(self, adapter: Any, indicators: list[Indicator], data: Agent5aInput):
        name = "cisa_kev"
        cves = [i for i in indicators if i.indicator_type == IndicatorType.CVE]
        if not cves:
            return [], FeedStatus(feed=name, state=FeedState.NO_MATCH), []
        if adapter is None:
            return [], FeedStatus(feed=name, state=FeedState.UNAVAILABLE, error="adapter not configured"), [f"{name}: adapter not configured"]
        method = getattr(adapter, "get_cisa_kev", None)
        if not callable(method):
            return [], FeedStatus(feed=name, state=FeedState.UNAVAILABLE, error="missing get_cisa_kev"), [f"{name}: missing get_cisa_kev"]
        try:
            raw = self._call_with_timeout(method)
            if not isinstance(raw, list):
                raise TypeError("CISA KEV response must be a list")
            by_cve = {i.normalized_value: i for i in cves}
            matches = []
            for item in raw:
                cve = str(_value(item, "cveID", _value(item, "cve_id", ""))).lower()
                if cve in by_cve:
                    matches.append(self._match("cisa_kev", by_cve[cve], item, data)[0])
            return matches, self._status(name, adapter, len(matches), []), []
        except FuturesTimeoutError:
            return [], FeedStatus(feed=name, state=FeedState.TIMEOUT, error="request timed out"), [f"{name}: timeout"]
        except Exception as exc:
            return [], FeedStatus(feed=name, state=FeedState.MALFORMED, error=str(exc)), [f"{name}: {type(exc).__name__}: {exc}"]

    def _match(self, source: str, indicator: Indicator, raw: Any, data: Agent5aInput):
        record_id = str(_value(raw, "id", _value(raw, "match_id", _value(raw, "cveID", "")))) or None
        description = _value(raw, "description", _value(raw, "shortDescription", _value(raw, "summary", None)))
        sanitized = blocked = 0
        if description:
            sanitized = 1
            description = self.gateway.sanitize(str(description), "description")
            blocked = int("Potential prompt injection blocked" in description or "SANITISED" in description)
        provenance = Provenance(source=source, source_record_id=record_id, finding_ids=indicator.finding_ids, indicator=indicator.normalized_value)
        valid = bool(indicator.finding_ids and data.case_id and data.tenant_id and source and indicator.normalized_value)
        match = ThreatMatch(
            indicator=indicator, source=source, match_id=record_id,
            title=_value(raw, "title", _value(raw, "name", None)),
            description=description, confidence=_value(raw, "confidence", None),
            tags=_value(raw, "tags", []) if isinstance(_value(raw, "tags", []), list) else [],
            provenance=provenance,
            validation=ValidationResult(citation_valid=valid, provenance_valid=valid),
        )
        return match, sanitized, blocked

    def _status(self, name: str, adapter: Any, count: int, errors: list[str]) -> FeedStatus:
        updated = adapter_timestamp(adapter)
        max_age = adapter_max_age(adapter)
        age = (datetime.now(timezone.utc) - updated).total_seconds() if updated else None
        if errors:
            state = FeedState.TIMEOUT if any("timeout" in error for error in errors) else FeedState.ERROR
        elif updated and max_age is not None and age is not None and age > max_age:
            state = FeedState.STALE
        else:
            state = FeedState.HEALTHY if count else FeedState.NO_MATCH
        return FeedStatus(feed=name, state=state, last_updated=updated, age_seconds=age, max_age_seconds=max_age, match_count=count, error="; ".join(errors) or None)

    def _call_with_timeout(self, method: Any, *args: Any) -> Any:
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(method, *args).result(timeout=self.timeout_seconds)

    @staticmethod
    def _as_dict(value: Any) -> dict:
        return value.model_dump(mode="json") if hasattr(value, "model_dump") else (value if isinstance(value, dict) else {})

    @staticmethod
    def _findings(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if hasattr(value, "model_dump"):
            return [value.model_dump()]
        return []
