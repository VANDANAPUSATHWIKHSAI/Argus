"""
Agent 5b — Validated Case Repository & Qdrant Interface
======================================================
Provides tenant-isolated storage and retrieval of Maker-Checker validated cases.

Enforces strict policies:
1. Only approved / validated cases can be indexed or retrieved.
2. Tenant isolation via per-tenant collections and payload verification.
3. Forbids storing raw forensic evidence (memory dumps, disks, PCAPs, passwords).
4. Deduplicates retrieved cases before scoring.
5. Neutralizes prompt injections in historical summaries and analyst notes.
6. Graceful handling of Qdrant connection errors and malformed payloads.
"""

from typing import List, Dict, Any, Optional, Tuple
import logging
import uuid
import re
from pydantic import ValidationError

from agents.agent5b_campaign_similarity.schemas import (
    ValidatedCase,
    MultiVector,
    RetrievedHistoricalCase,
    CaseValidationRecord
)
from agents.agent5b_campaign_similarity.vector_engine import MultiVectorEngine

try:
    from qdrant_client import QdrantClient, models
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    QdrantClient = None
    models = None

logger = logging.getLogger(__name__)

FORBIDDEN_RAW_KEYS = {
    "raw_evidence", "disk_image", "memory_dump", "memory_raw", "pcap",
    "pcap_raw", "password", "passwords", "registry_hive", "raw_payload"
}

# Prompt injection markers to neutralize in untrusted historical text
INJECTION_MARKERS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+|an\s+)?", re.IGNORECASE),
    re.compile(r"bypass\s+all\s+security\s+rules", re.IGNORECASE)
]


class ValidatedCaseRepository:
    """
    Manages historical validated cases in Qdrant with tenant isolation and Maker-Checker validation.
    """

    def __init__(
        self,
        qdrant_client: Optional[Any] = None,
        vector_engine: Optional[MultiVectorEngine] = None,
        url: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        self.vector_engine = vector_engine or MultiVectorEngine()

        self.is_degraded = False
        self.is_in_memory_fallback = False

        if qdrant_client is not None:
            self.client = qdrant_client
        elif QDRANT_AVAILABLE:
            from config.settings import settings
            is_prod = getattr(settings, "app_env", "development") == "production"
            target_url = url or getattr(settings, "qdrant_url", None)
            target_key = api_key or getattr(settings, "qdrant_api_key", None)
            if target_url:
                try:
                    self.client = QdrantClient(url=target_url, api_key=target_key)
                except Exception as e:
                    if is_prod:
                        logger.error("Failed to connect to Qdrant at %s in production mode: %s", target_url, e)
                        raise RuntimeError(f"Qdrant service connection failed in production mode: {e}") from e
                    logger.warning("Failed to connect to Qdrant at %s: %s. Using isolated in-memory development fallback.", target_url, e)
                    self.client = QdrantClient(":memory:")
                    self.is_in_memory_fallback = True
                    self.is_degraded = True
            else:
                if is_prod:
                    raise RuntimeError("Qdrant URL not configured in production mode.")
                self.client = QdrantClient(":memory:")
                self.is_in_memory_fallback = True
        else:
            self.client = None
            self.is_degraded = True

        self._in_memory_cases: Dict[str, Dict[str, Tuple[ValidatedCase, MultiVector]]] = {}

    def _get_collection_name(self, tenant_id: str) -> str:
        clean_tenant = tenant_id.strip().lower().replace("-", "_").replace(" ", "_")
        return f"validated_cases_{clean_tenant}"

    def is_tenant_ready(self, tenant_id: str) -> bool:
        """
        Verifies if a tenant's Qdrant collection is fully initialized, operational,
        and conforms to the multi-vector schema. Prevents partially initialized
        or degraded tenants from appearing ready.
        """
        clean_tenant = (tenant_id or "").strip()
        if not clean_tenant or clean_tenant in ("*", "none", "null"):
            return False

        if not self.client or not QDRANT_AVAILABLE:
            return False

        col_name = self._get_collection_name(clean_tenant)
        try:
            exists = False
            if hasattr(self.client, "collection_exists"):
                exists = self.client.collection_exists(col_name)
            elif hasattr(self.client, "get_collections"):
                cols = self.client.get_collections().collections
                exists = any(c.name == col_name for c in cols)

            if not exists:
                return False

            # Retrieve collection info to verify vector config and status
            col_info = self.client.get_collection(col_name)

            # 1. Verify status is healthy
            status_val = str(getattr(col_info, "status", "")).lower()
            if status_val and ("red" in status_val or "grey" in status_val or "error" in status_val):
                return False

            # 2. Verify all 4 required named vectors exist with matching dimension
            params = getattr(col_info.config, "params", None)
            vectors_map = getattr(params, "vectors", None)
            required_vectors = {"behavior", "attack", "threat_intel", "composite"}
            expected_dim = self.vector_engine.VECTOR_DIM

            if not isinstance(vectors_map, dict):
                return False

            for req_vec in required_vectors:
                if req_vec not in vectors_map:
                    return False
                vec_param = vectors_map[req_vec]
                vec_size = getattr(vec_param, "size", None)
                if vec_size != expected_dim:
                    return False

            return True
        except Exception as e:
            logger.debug(f"is_tenant_ready check returned False for {clean_tenant}: {e}")
            return False

    def provision_tenant(self, tenant_id: str, force_recreate: bool = False) -> Dict[str, Any]:
        """
        Provisions a fresh tenant collection in Qdrant with deterministic multi-vector schema.
        Safe to retry: if collection already exists and is ready, it is validated and preserved.
        If partially initialized or force_recreate is True, it is cleanly re-created.
        Returns detailed status metadata.
        """
        clean_tenant = (tenant_id or "").strip()
        if not clean_tenant or clean_tenant in ("*", "none", "null"):
            raise ValueError(f"Invalid tenant_id for Qdrant provisioning: '{tenant_id}'")

        if not self.client or not QDRANT_AVAILABLE:
            raise RuntimeError("Qdrant client unavailable for tenant provisioning.")

        col_name = self._get_collection_name(clean_tenant)
        dim = self.vector_engine.VECTOR_DIM
        required_vectors = ["behavior", "attack", "threat_intel", "composite"]

        # Check existing readiness
        if not force_recreate and self.is_tenant_ready(clean_tenant):
            info = self.client.get_collection(col_name)
            return {
                "tenant_id": clean_tenant,
                "collection_name": col_name,
                "status": "READY",
                "is_ready": True,
                "vector_dim": dim,
                "vectors": required_vectors,
                "points_count": getattr(info, "points_count", 0),
                "recreated": False,
            }

        # If collection exists partially initialized or corrupted, delete before recreating
        exists = False
        try:
            if hasattr(self.client, "collection_exists"):
                exists = self.client.collection_exists(col_name)
            elif hasattr(self.client, "get_collections"):
                cols = self.client.get_collections().collections
                exists = any(c.name == col_name for c in cols)
        except Exception:
            pass

        if exists:
            logger.warning(f"Removing partially initialized or recreating collection '{col_name}' for tenant '{clean_tenant}'")
            try:
                self.client.delete_collection(col_name)
            except Exception as de:
                logger.warning(f"Error during delete_collection for {col_name}: {de}")

        # Create fresh collection with full multi-vector config
        vec_config = {
            "behavior": models.VectorParams(size=dim, distance=models.Distance.COSINE),
            "attack": models.VectorParams(size=dim, distance=models.Distance.COSINE),
            "threat_intel": models.VectorParams(size=dim, distance=models.Distance.COSINE),
            "composite": models.VectorParams(size=dim, distance=models.Distance.COSINE)
        }

        self.client.create_collection(
            collection_name=col_name,
            vectors_config=vec_config
        )

        # Immediate post-creation verification
        if not self.is_tenant_ready(clean_tenant):
            raise RuntimeError(
                f"Fresh tenant provisioning post-check failed for tenant '{clean_tenant}'. Collection '{col_name}' is not ready."
            )

        info = self.client.get_collection(col_name)
        return {
            "tenant_id": clean_tenant,
            "collection_name": col_name,
            "status": "READY",
            "is_ready": True,
            "vector_dim": dim,
            "vectors": required_vectors,
            "points_count": getattr(info, "points_count", 0),
            "recreated": True,
        }

    def ensure_collection(self, tenant_id: str) -> bool:
        if not self.client or not QDRANT_AVAILABLE:
            return False

        try:
            if self.is_tenant_ready(tenant_id):
                return True
            res = self.provision_tenant(tenant_id)
            return res.get("is_ready", False)
        except Exception as e:
            from config.settings import settings
            is_prod = getattr(settings, "app_env", "development") == "production"
            if is_prod:
                raise RuntimeError(f"Qdrant collection creation failed in production mode: {e}") from e
            logger.error(f"Error ensuring Qdrant collection for tenant {tenant_id}: {e}")
            self.is_degraded = True
            return False


    def add_case(self, case: ValidatedCase, vectors: Optional[MultiVector] = None) -> bool:
        """
        Indexes a case into the tenant's validated case repository.
        Strictly enforces Maker-Checker approval and rejects raw evidence.
        """
        # 1. Maker-Checker Enforcement
        if case.validation.status not in ["approved", "validated"]:
            raise ValueError(
                f"Maker-Checker policy violation: Case '{case.case_id}' has status '{case.validation.status}'. "
                f"Only approved/validated cases can be stored in ValidatedCaseRepository."
            )
        if not case.validation.approved_by:
            raise ValueError(
                f"Maker-Checker policy violation: Case '{case.case_id}' lacks an approver signature."
            )

        # 2. Reject / Strip Forbidden Raw Forensic Evidence & Neutralize Injections
        case_dict = case.model_dump()
        self._sanitize_raw_evidence(case_dict)
        self._neutralize_text_injections(case_dict)

        case = ValidatedCase(**case_dict)
        tenant_id = case.tenant_id or "default"

        if vectors is None:
            vectors = self._generate_vectors_for_case(case)

        if tenant_id not in self._in_memory_cases:
            self._in_memory_cases[tenant_id] = {}
        self._in_memory_cases[tenant_id][case.case_id] = (case, vectors)

        if self.client and QDRANT_AVAILABLE:
            try:
                self.ensure_collection(tenant_id)
                col_name = self._get_collection_name(tenant_id)
                point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{tenant_id}:{case.case_id}"))

                point = models.PointStruct(
                    id=point_id,
                    vector={
                        "behavior": vectors.behavior_vector,
                        "attack": vectors.attack_pattern_vector,
                        "threat_intel": vectors.threat_intel_vector,
                        "composite": vectors.composite_vector
                    },
                    payload=case.model_dump()
                )
                self.client.upsert(collection_name=col_name, points=[point])
                return True
            except Exception as e:
                from config.settings import settings
                is_prod = getattr(settings, "app_env", "development") == "production"
                if is_prod:
                    raise RuntimeError(f"Qdrant case insertion failed in production mode: {e}") from e
                logger.error(f"Error inserting case {case.case_id} into Qdrant: {e}")
                self.is_degraded = True
                return False

        return True


    def search_similar(
        self,
        tenant_id: str,
        query_vectors: MultiVector,
        top_k: int = 5,
        dimension: str = "composite"
    ) -> List[RetrievedHistoricalCase]:
        """
        Searches validated cases within the tenant partition.
        Deduplicates, validates payloads, and excludes unapproved cases.
        """
        target_vec = getattr(query_vectors, f"{dimension}_vector", query_vectors.composite_vector)
        if not target_vec or all(v == 0.0 for v in target_vec):
            target_vec = query_vectors.composite_vector

        if self.client and QDRANT_AVAILABLE:
            try:
                col_name = self._get_collection_name(tenant_id)
                dim_name = "composite" if dimension == "composite" else ("attack" if dimension == "attack_pattern" else dimension)

                res = None
                if hasattr(self.client, "query_points"):
                    res = self.client.query_points(
                        collection_name=col_name,
                        query=target_vec,
                        using=dim_name,
                        limit=top_k * 3
                    )
                    points = res.points if res else []
                elif hasattr(self.client, "search"):
                    points = self.client.search(
                        collection_name=col_name,
                        query_vector=(dim_name, target_vec),
                        limit=top_k * 3
                    )
                else:
                    points = []

                retrieved: List[RetrievedHistoricalCase] = []
                seen_case_ids = set()

                for pt in points:
                    payload = pt.payload or {}
                    try:
                        self._neutralize_text_injections(payload)
                        val_case = ValidatedCase(**payload)
                    except (ValidationError, Exception) as pe:
                        logger.warning(f"Malformed historical case payload in Qdrant (ID {pt.id}): {pe}. Skipping.")
                        continue

                    # Strict tenant check
                    clean_target = tenant_id.strip().lower().replace("-", "_").replace(" ", "_")
                    clean_case_tenant = val_case.tenant_id.strip().lower().replace("-", "_").replace(" ", "_")
                    if clean_case_tenant != clean_target:
                        logger.warning(f"Cross-tenant payload leak prevented! Target: {tenant_id}, Case: {val_case.tenant_id}")
                        continue

                    # Strict validation check
                    if val_case.validation.status not in ["approved", "validated"] or not val_case.validation.approved_by:
                        logger.warning(f"Unapproved case {val_case.case_id} excluded from retrieval.")
                        continue

                    # Deduplication
                    if val_case.case_id in seen_case_ids:
                        continue
                    seen_case_ids.add(val_case.case_id)

                    case_vecs = self._generate_vectors_for_case(val_case)
                    b_sim = MultiVectorEngine.cosine_similarity(query_vectors.behavior_vector, case_vecs.behavior_vector)
                    a_sim = MultiVectorEngine.cosine_similarity(query_vectors.attack_pattern_vector, case_vecs.attack_pattern_vector)
                    ti_sim = MultiVectorEngine.cosine_similarity(query_vectors.threat_intel_vector, case_vecs.threat_intel_vector)
                    c_sim = MultiVectorEngine.cosine_similarity(query_vectors.composite_vector, case_vecs.composite_vector)

                    retrieved.append(RetrievedHistoricalCase(
                        case_id=val_case.case_id,
                        tenant_id=val_case.tenant_id,
                        similarity_score=float(c_sim),
                        behavior_similarity=float(b_sim),
                        attack_similarity=float(a_sim),
                        intelligence_similarity=float(ti_sim),
                        case_data=val_case
                    ))

                retrieved.sort(key=lambda x: x.similarity_score, reverse=True)
                return retrieved[:top_k]

            except Exception as e:
                from config.settings import settings
                is_prod = getattr(settings, "app_env", "development") == "production"
                if is_prod:
                    raise RuntimeError(f"Qdrant search query failed in production mode: {e}") from e
                logger.warning(f"Qdrant query failed: {e}. Falling back to memory index.")
                self.is_degraded = True

        return self._search_in_memory(tenant_id, query_vectors, top_k)


    def _search_in_memory(
        self,
        tenant_id: str,
        query_vectors: MultiVector,
        top_k: int
    ) -> List[RetrievedHistoricalCase]:
        tenant_cases = self._in_memory_cases.get(tenant_id, {})
        retrieved: List[RetrievedHistoricalCase] = []
        seen_case_ids = set()

        for case_id, (val_case, case_vecs) in tenant_cases.items():
            clean_target = tenant_id.strip().lower().replace("-", "_").replace(" ", "_")
            clean_case_tenant = val_case.tenant_id.strip().lower().replace("-", "_").replace(" ", "_")
            if clean_case_tenant != clean_target:
                continue
            if val_case.validation.status not in ["approved", "validated"] or not val_case.validation.approved_by:
                continue
            if val_case.case_id in seen_case_ids:
                continue
            seen_case_ids.add(val_case.case_id)

            b_sim = MultiVectorEngine.cosine_similarity(query_vectors.behavior_vector, case_vecs.behavior_vector)
            a_sim = MultiVectorEngine.cosine_similarity(query_vectors.attack_pattern_vector, case_vecs.attack_pattern_vector)
            ti_sim = MultiVectorEngine.cosine_similarity(query_vectors.threat_intel_vector, case_vecs.threat_intel_vector)
            c_sim = MultiVectorEngine.cosine_similarity(query_vectors.composite_vector, case_vecs.composite_vector)

            retrieved.append(RetrievedHistoricalCase(
                case_id=val_case.case_id,
                tenant_id=val_case.tenant_id,
                similarity_score=float(c_sim),
                vector_retrieval_similarity=float(c_sim),
                behavior_similarity=float(b_sim),
                attack_similarity=float(a_sim),
                intelligence_similarity=float(ti_sim),
                case_data=val_case
            ))

        retrieved.sort(key=lambda x: x.similarity_score, reverse=True)
        return retrieved[:top_k]

    def _generate_vectors_for_case(self, case: ValidatedCase) -> MultiVector:
        fp = case.malware_behavior_fingerprint or {}
        b_parts = [f"{k}: {', '.join(v)}" for k, v in fp.items() if v]
        b_text = " | ".join(b_parts)

        ap = case.attack_pattern or {}
        a_parts = [f"{k}: {v}" for k, v in ap.items() if v]
        a_text = " | ".join(a_parts)

        ti = case.threat_intelligence or {}
        ti_parts = [f"family: {case.malware_identity.family}"]
        if ti.get("mitre_techniques"):
            ti_parts.append(f"mitre: {', '.join(ti['mitre_techniques'])}")
        if ti.get("cves"):
            ti_parts.append(f"cves: {', '.join(ti['cves'])}")
        ti_text = " | ".join(ti_parts)

        comp_text = f"BEHAVIOR: {b_text}\nATTACK: {a_text}\nTHREAT_INTEL: {ti_text}"

        return MultiVector(
            behavior_vector=self.vector_engine.encode_text(b_text),
            attack_pattern_vector=self.vector_engine.encode_text(a_text),
            threat_intel_vector=self.vector_engine.encode_text(ti_text),
            composite_vector=self.vector_engine.encode_text(comp_text)
        )

    def _sanitize_raw_evidence(self, data: Any):
        if isinstance(data, dict):
            for k in list(data.keys()):
                if k.lower() in FORBIDDEN_RAW_KEYS:
                    logger.warning(f"Stripping forbidden raw forensic evidence key: {k}")
                    del data[k]
                else:
                    self._sanitize_raw_evidence(data[k])
        elif isinstance(data, list):
            for item in data:
                self._sanitize_raw_evidence(item)

    @classmethod
    def _neutralize_text_injections(cls, data: Any):
        """
        Neutralizes prompt injections in untrusted historical text fields.
        """
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str):
                    for pat in INJECTION_MARKERS:
                        if pat.search(v):
                            logger.warning(f"Prompt injection pattern detected and neutralized in historical field '{k}'")
                            data[k] = pat.sub("[NEUTRALIZED_UNTRUSTED_INSTRUCTION]", v)
                else:
                    cls._neutralize_text_injections(v)
        elif isinstance(data, list):
            for item in data:
                cls._neutralize_text_injections(item)
