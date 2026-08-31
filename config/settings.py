from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    # ── LLM ──────────────────────────────────────
    llm_model_name: str = "Qwen/Qwen3-14B"
    llm_fallback_model: str = "Qwen/Qwen3-8B"
    embedding_model: str = "Qwen/Qwen3-Embedding-4B"

    # ── PostgreSQL (structured data) ─────────────
    # FIR findings, case sessions, audit logs,
    # agent outputs, confidence scores, ISM state
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "argus"
    postgres_user: str = "argus_user"
    postgres_password: str = "argus_dev"
    postgres_url: str = "postgresql://argus_user:argus_dev@localhost:5432/argus"

    # ── MinIO (raw evidence object storage) ──────
    # Original evidence files, memory dumps,
    # PCAP files, disk images — large binary blobs
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "argus_minio"
    minio_secret_key: str = "argus_minio_dev"
    minio_secure: bool = False
    minio_bucket_raw_evidence: str = "argus-raw-evidence"
    minio_bucket_encrypted: str = "argus-encrypted-evidence"

    # ── Neo4j (graph database) ───────────────────
    # Agent 2 (evidence correlation via GDS)
    # Agent 3 (MITRE ATT&CK kill-chain traversal)
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "argus_dev"

    # ── Qdrant (vector database) ─────────────────
    # Agent 5b — RAG against Validated Case Repository
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: Optional[str] = None

    # ── Threat Intel ─────────────────────────────
    taxii_server_url: Optional[str] = None
    taxii_api_key: Optional[str] = None
    nvd_api_key: Optional[str] = None
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # ── Security ─────────────────────────────────
    evidence_encryption_key: Optional[str] = None
    rfc3161_tsa_url: str = "https://freetsa.org/tsr"

    # ── App ──────────────────────────────────────
    app_env: str = "development"
    log_level: str = "INFO"


settings = Settings()

