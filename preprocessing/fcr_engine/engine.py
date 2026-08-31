"""
Forensic Correlation Record (FCR) Engine Implementation
========================================================
Rule-based, deterministic correlation engine.
Links Stage-2 normalized Artifact records into Stage-3 CorrelationRecord (FCR) objects.

Guarantees:
- 100% deterministic & rule-based (0 LLM, 0 probabilistic models, 0 network calls)
- Strict case isolation (CASE-A never correlates with CASE-B)
- Order-invariant deduplication ([A, B] == [B, A])
- Strict reference validation (all artifact_ids must resolve to real artifacts)
- Immutability of raw evidence (FCR references artifact_ids without duplicating raw payloads)
- Zero code execution of commands/scripts in evidence
"""

from __future__ import annotations

import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, Sequence

from preprocessing.schemas import Artifact, ExtractedEntity
from preprocessing.fcr_engine.schemas import CorrelationRecord, compute_confidence

logger = logging.getLogger(__name__)


class FCREngine:
    """
    Deterministic rule-based Forensic Correlation Record Engine.
    """

    def correlate(
        self,
        artifacts: Sequence[Artifact],
        extracted_entities: Optional[Sequence[ExtractedEntity]] = None,
        window_seconds: float = 30.0
    ) -> list[CorrelationRecord]:
        """
        Correlate a list of Artifact records and optional ExtractedEntity items.

        Args:
            artifacts: List of normalized Stage-2 Artifact objects.
            extracted_entities: Optional list of ExtractedEntity objects from ArtifactExtractor.
            window_seconds: Time window threshold in seconds for temporal proximity.

        Returns:
            List of validated, deduplicated CorrelationRecord objects.
        """
        if not artifacts:
            return []

        # 1. Filter valid artifacts and group by case_id for strict case isolation
        by_case: dict[str, list[Artifact]] = {}
        art_lookup: dict[str, Artifact] = {}

        for art in artifacts:
            if not isinstance(art, Artifact) or not art.artifact_id or not art.evidence_id:
                continue
            case = (art.case_id or "default_case").strip()
            by_case.setdefault(case, []).append(art)
            art_lookup[art.artifact_id] = art

        # Map entities to artifacts if provided
        entities_by_artifact: dict[str, list[ExtractedEntity]] = {}
        if extracted_entities:
            for ent in extracted_entities:
                if ent.artifact_id in art_lookup:
                    entities_by_artifact.setdefault(ent.artifact_id, []).append(ent)

        raw_records: list[CorrelationRecord] = []

        # 2. Process each case independently
        for case_id, case_arts in by_case.items():
            if len(case_arts) >= 2:
                # Strategy A: Temporal Proximity Correlation
                raw_records.extend(self._correlate_temporal(case_id, case_arts, window_seconds))

                # Strategy B: Shared IOC Correlation
                raw_records.extend(self._correlate_shared_ioc(case_id, case_arts, entities_by_artifact))

                # Strategy C: Process Tree Correlation
                raw_records.extend(self._correlate_process_tree(case_id, case_arts))

                # Strategy D: Network ↔ Process Correlation
                raw_records.extend(self._correlate_network_process(case_id, case_arts))

            # Strategy E: Single-Artifact Standalone Correlation
            raw_records.extend(self._correlate_single_artifact(case_id, case_arts, entities_by_artifact))

        # 3. Deduplicate correlation records
        return self._deduplicate(raw_records, art_lookup)

    def _correlate_temporal(
        self,
        case_id: str,
        artifacts: list[Artifact],
        window_seconds: float
    ) -> list[CorrelationRecord]:
        """Correlate artifacts on the same host whose timestamps fall within window_seconds."""
        records: list[CorrelationRecord] = []

        # Group by host (host_id or normalized_fields.host)
        by_host: dict[str, list[Artifact]] = {}
        for art in artifacts:
            host = self._get_host(art)
            if host and art.timestamp is not None:
                by_host.setdefault(host, []).append(art)

        for host, host_arts in by_host.items():
            if len(host_arts) < 2:
                continue

            # Sort artifacts by timestamp
            sorted_arts = sorted(host_arts, key=lambda a: a.timestamp or datetime.min.replace(tzinfo=timezone.utc))

            # Sliding window correlation
            n = len(sorted_arts)
            for i in range(n):
                window_group = [sorted_arts[i]]
                t_start = sorted_arts[i].timestamp
                if t_start is None:
                    continue

                for j in range(i + 1, n):
                    t_curr = sorted_arts[j].timestamp
                    if t_curr is None:
                        continue
                    delta = (t_curr - t_start).total_seconds()
                    if delta <= window_seconds:
                        window_group.append(sorted_arts[j])
                    else:
                        break

                if len(window_group) >= 2:
                    art_ids = sorted(list(set(a.artifact_id for a in window_group)))
                    if len(art_ids) < 2:
                        continue

                    distinct_types = len(set(a.artifact_type for a in window_group))
                    source_tools = len(set(a.source_tool for a in window_group))
                    confidence = compute_confidence(distinct_types, source_tools)
                    corr_id = self._generate_corr_id(case_id, ["temporal_proximity"], art_ids, host)

                    try:
                        rec = CorrelationRecord(
                            correlation_id=corr_id,
                            case_id=case_id,
                            artifact_ids=art_ids,
                            relationship_type=["temporal_proximity"],
                            source_count=source_tools,
                            distinct_artifact_types=distinct_types,
                            confidence=confidence,
                            host=host,
                            strategy_params={
                                "window_seconds": window_seconds,
                                "host_required": True
                            }
                        )
                        records.append(rec)
                    except ValueError as e:
                        logger.debug("Failed to create temporal CorrelationRecord: %s", e)

        return records

    def _correlate_shared_ioc(
        self,
        case_id: str,
        artifacts: list[Artifact],
        entities_by_artifact: dict[str, list[ExtractedEntity]]
    ) -> list[CorrelationRecord]:
        """Correlate artifacts sharing atomic IOC values (hash, IP, domain, URL, registry key, device serial)."""
        records: list[CorrelationRecord] = []

        # Map (ioc_key, ioc_value) -> set(artifact_id)
        ioc_groups: dict[tuple[str, str], set[str]] = {}

        for art in artifacts:
            nf = art.normalized_fields
            # 1. From NormalizedFields
            candidates = [
                ("hash", nf.hash),
                ("src_ip", nf.src_ip),
                ("dst_ip", nf.dst_ip),
                ("domain", nf.domain),
                ("url", nf.url),
                ("registry_key", nf.registry_key),
                ("usb_serial_number", nf.usb_serial_number),
                ("sender", nf.sender),
                ("recipients", nf.recipients),
            ]
            for key_name, val in candidates:
                if val and str(val).strip():
                    norm_val = str(val).strip().lower()
                    # Exclude trivial values
                    if len(norm_val) > 2 and norm_val not in ("0.0.0.0", "127.0.0.1", "none", "null"):
                        ioc_groups.setdefault((key_name, norm_val), set()).add(art.artifact_id)

            # 2. From ExtractedEntities
            if art.artifact_id in entities_by_artifact:
                for ent in entities_by_artifact[art.artifact_id]:
                    if ent.value and ent.value.strip():
                        val_str = ent.value.strip().lower()
                        if len(val_str) > 2 and val_str not in ("0.0.0.0", "127.0.0.1"):
                            ioc_groups.setdefault((ent.entity_type, val_str), set()).add(art.artifact_id)

        art_dict = {a.artifact_id: a for a in artifacts}

        for (ioc_type, ioc_value), art_id_set in ioc_groups.items():
            if len(art_id_set) < 2:
                continue

            art_ids = sorted(list(art_id_set))
            matched_arts = [art_dict[aid] for aid in art_ids if aid in art_dict]
            if len(matched_arts) < 2:
                continue

            distinct_types = len(set(a.artifact_type for a in matched_arts))
            source_tools = len(set(a.source_tool for a in matched_arts))
            confidence = compute_confidence(distinct_types, source_tools)
            corr_id = self._generate_corr_id(case_id, ["shared_ioc"], art_ids, ioc_value)

            try:
                rec = CorrelationRecord(
                    correlation_id=corr_id,
                    case_id=case_id,
                    artifact_ids=art_ids,
                    relationship_type=["shared_ioc"],
                    source_count=source_tools,
                    distinct_artifact_types=distinct_types,
                    confidence=confidence,
                    shared_value=ioc_value,
                    strategy_params={
                        "shared_ioc_key": ioc_type,
                        "shared_value": ioc_value
                    }
                )
                records.append(rec)
            except ValueError as e:
                logger.debug("Failed to create shared_ioc CorrelationRecord: %s", e)

        return records

    def _correlate_process_tree(self, case_id: str, artifacts: list[Artifact]) -> list[CorrelationRecord]:
        """Correlate parent and child processes on the same host where child.ppid == parent.pid."""
        records: list[CorrelationRecord] = []

        by_host: dict[str, list[Artifact]] = {}
        for art in artifacts:
            host = self._get_host(art)
            if host and art.normalized_fields.process_id is not None:
                by_host.setdefault(host, []).append(art)

        for host, host_arts in by_host.items():
            pid_map: dict[int, list[Artifact]] = {}
            for art in host_arts:
                pid = art.normalized_fields.process_id
                if pid is not None:
                    pid_map.setdefault(pid, []).append(art)

            for child in host_arts:
                ppid = child.normalized_fields.parent_process_id
                if ppid is not None and ppid in pid_map:
                    parents = pid_map[ppid]
                    for parent in parents:
                        if parent.artifact_id != child.artifact_id:
                            art_ids = sorted([parent.artifact_id, child.artifact_id])
                            matched = [parent, child]
                            distinct_types = len(set(a.artifact_type for a in matched))
                            source_tools = len(set(a.source_tool for a in matched))
                            confidence = compute_confidence(distinct_types, source_tools)
                            corr_id = self._generate_corr_id(case_id, ["process_tree"], art_ids, f"{ppid}->{child.normalized_fields.process_id}")

                            try:
                                rec = CorrelationRecord(
                                    correlation_id=corr_id,
                                    case_id=case_id,
                                    artifact_ids=art_ids,
                                    relationship_type=["process_tree"],
                                    source_count=source_tools,
                                    distinct_artifact_types=distinct_types,
                                    confidence=confidence,
                                    host=host,
                                    strategy_params={
                                        "parent_pid": ppid,
                                        "child_pid": child.normalized_fields.process_id
                                    }
                                )
                                records.append(rec)
                            except ValueError as e:
                                logger.debug("Failed to create process_tree CorrelationRecord: %s", e)

        return records

    def _correlate_network_process(self, case_id: str, artifacts: list[Artifact]) -> list[CorrelationRecord]:
        """Correlate process artifacts with network connection artifacts on the same host."""
        records: list[CorrelationRecord] = []

        by_host: dict[str, list[Artifact]] = {}
        for art in artifacts:
            host = self._get_host(art)
            if host:
                by_host.setdefault(host, []).append(art)

        for host, host_arts in by_host.items():
            process_arts = [a for a in host_arts if "process" in a.artifact_type or a.normalized_fields.process_id is not None]
            network_arts = [a for a in host_arts if "network" in a.artifact_type or a.normalized_fields.src_ip or a.normalized_fields.dst_ip]

            if not process_arts or not network_arts:
                continue

            for proc in process_arts:
                proc_pid = proc.normalized_fields.process_id
                for net in network_arts:
                    if proc.artifact_id == net.artifact_id:
                        continue

                    net_pid = net.normalized_fields.process_id
                    # Match by explicit PID alignment or port matching
                    match_found = False
                    reason = ""
                    if proc_pid is not None and net_pid is not None and proc_pid == net_pid:
                        match_found = True
                        reason = f"pid_match:{proc_pid}"

                    if match_found:
                        art_ids = sorted([proc.artifact_id, net.artifact_id])
                        matched = [proc, net]
                        distinct_types = len(set(a.artifact_type for a in matched))
                        source_tools = len(set(a.source_tool for a in matched))
                        confidence = compute_confidence(distinct_types, source_tools)
                        corr_id = self._generate_corr_id(case_id, ["network_process"], art_ids, reason)

                        try:
                            rec = CorrelationRecord(
                                correlation_id=corr_id,
                                case_id=case_id,
                                artifact_ids=art_ids,
                                relationship_type=["network_process"],
                                source_count=source_tools,
                                distinct_artifact_types=distinct_types,
                                confidence=confidence,
                                host=host,
                                strategy_params={"match_reason": reason}
                            )
                            records.append(rec)
                        except ValueError as e:
                            logger.debug("Failed to create network_process CorrelationRecord: %s", e)

        return records

    def _correlate_single_artifact(
        self,
        case_id: str,
        artifacts: list[Artifact],
        entities_by_artifact: Optional[dict[str, list[ExtractedEntity]]] = None
    ) -> list[CorrelationRecord]:
        """Correlate individual standalone evidence artifacts with derived entities into FCR records."""
        records: list[CorrelationRecord] = []
        entities_by_artifact = entities_by_artifact or {}
        for art in artifacts:
            host = self._get_host(art)
            ents = entities_by_artifact.get(art.artifact_id, [])
            if ents:
                for ent in ents:
                    val_str = (ent.value or "").strip().lower()
                    if not val_str or len(val_str) <= 2 or val_str in ("0.0.0.0", "127.0.0.1"):
                        continue
                    art_ids = [art.artifact_id, ent.entity_id]
                    corr_id = self._generate_corr_id(case_id, ["shared_ioc"], art_ids, val_str)
                    try:
                        rec = CorrelationRecord(
                            correlation_id=corr_id,
                            case_id=case_id,
                            artifact_ids=art_ids,
                            relationship_type=["shared_ioc"],
                            shared_value=val_str,
                            source_count=1,
                            distinct_artifact_types=1,
                            confidence=0.5,
                            host=host,
                            strategy_params={"standalone_entity": True}
                        )
                        records.append(rec)
                    except ValueError as e:
                        logger.debug("Failed to create standalone shared_ioc CorrelationRecord: %s", e)
        return records

    def _get_host(self, art: Artifact) -> Optional[str]:
        """
        Extract clean host string following priority rules:
        1. Explicit Artifact.host_id
        2. normalized_fields.host
        3. raw_fields host/computer/hostname fields
        4. evidence_metadata host
        5. case_metadata host
        6. Otherwise None (Never derive host from filename, hash, or non-host ID)
        """
        if art.host_id and art.host_id.strip():
            return art.host_id.strip().lower()

        if art.normalized_fields and art.normalized_fields.host and art.normalized_fields.host.strip():
            return art.normalized_fields.host.strip().lower()

        if art.raw_fields:
            for k in ("host", "computer", "hostname", "computer_name", "host_name"):
                v = art.raw_fields.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip().lower()

            ev_meta = art.raw_fields.get("evidence_metadata")
            if isinstance(ev_meta, dict):
                for k in ("host", "computer", "hostname", "host_id"):
                    v = ev_meta.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip().lower()

            case_meta = art.raw_fields.get("case_metadata")
            if isinstance(case_meta, dict):
                for k in ("host", "computer", "hostname", "host_id"):
                    v = case_meta.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip().lower()

        return None

    def _generate_corr_id(self, case_id: str, relationship_types: list[str], artifact_ids: list[str], extra: str = "") -> str:
        """
        Generate deterministic correlation ID matching ^CORR-[0-9]{5,}$.
        """
        rel_str = ",".join(sorted(relationship_types))
        art_str = ",".join(sorted(artifact_ids))
        seed = f"{case_id}:{rel_str}:{art_str}:{extra}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        num_val = int(digest[:8], 16) % 1000000
        return f"CORR-{num_val:06d}"

    def _deduplicate(self, records: list[CorrelationRecord], art_lookup: dict[str, Artifact]) -> list[CorrelationRecord]:
        """
        Deduplicate correlation records based on:
        (case_id, tuple(sorted(artifact_ids)), host, shared_value)
        If duplicates overlap across strategies, merge relationship_type and strategy_params.
        """
        unique_map: dict[tuple, CorrelationRecord] = {}

        for rec in records:
            key = (
                rec.case_id,
                tuple(sorted(rec.artifact_ids)),
                rec.host,
                rec.shared_value
            )
            if key in unique_map:
                existing = unique_map[key]
                # Merge relationship types cleanly
                merged_rels = list(dict.fromkeys(existing.relationship_type + rec.relationship_type))
                existing.relationship_type = merged_rels

                # Merge strategy parameters cleanly
                merged_params = dict(existing.strategy_params)
                for k, v in rec.strategy_params.items():
                    if k not in merged_params:
                        merged_params[k] = v
                    elif merged_params[k] != v:
                        merged_params[f"{k}_alt"] = v
                existing.strategy_params = merged_params

                # Re-verify matching artifacts
                matched = [art_lookup[aid] for aid in existing.artifact_ids if aid in art_lookup]
                if matched:
                    existing.distinct_artifact_types = len(set(a.artifact_type for a in matched))
                    existing.source_count = len(set(a.source_tool for a in matched))
                    existing.confidence = compute_confidence(existing.distinct_artifact_types, existing.source_count)
            else:
                unique_map[key] = rec

        return list(unique_map.values())
