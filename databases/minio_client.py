# ──────────────────────────────────────────────────────────────
# MinIO Client — Raw Evidence Object Storage
# ──────────────────────────────────────────────────────────────
# What is stored here:
#   - Original evidence files EXACTLY as uploaded (immutable)
#   - Encrypted evidence blobs (post-hashing)
#   - Memory dumps (.raw, .dmp, .mem)
#   - PCAP files (.pcap, .pcapng)
#   - Disk images (.dd, .img, .e01)
#   - Any large binary artifact that should not go into PostgreSQL
#
# Bucket structure:
#   argus-raw-evidence/
#     └── {tenant_id}/{case_id}/{evidence_id}/original/{filename}
#   argus-encrypted-evidence/
#     └── {tenant_id}/{case_id}/{evidence_id}/encrypted/{filename}.enc
#
# MinIO is S3-compatible — boto3 also works, but minio-py is lighter.
# ──────────────────────────────────────────────────────────────

import io
from pathlib import Path
from typing import Optional, BinaryIO
from minio import Minio
from minio.error import S3Error
from config.settings import settings


class MinioClient:
    """
    MinIO client for raw evidence object storage.
    S3-compatible API — handles all large binary artifacts.
    """

    RAW_BUCKET = "argus-raw-evidence"
    ENCRYPTED_BUCKET = "argus-encrypted-evidence"

    def __init__(self):
        self.client = Minio(
            endpoint=settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )

    def ensure_buckets(self):
        """Create required buckets if they don't exist (called on startup)."""
        for bucket in [self.RAW_BUCKET, self.ENCRYPTED_BUCKET]:
            if not self.client.bucket_exists(bucket):
                self.client.make_bucket(bucket)
                # Set bucket to immutable (no delete policy in dev;
                # use Object Lock in production for legal hold)
                print(f"[MinIO] Created bucket: {bucket}")

    def _object_key(
        self, tenant_id: str, case_id: str, evidence_id: str, filename: str
    ) -> str:
        """Generate a deterministic, namespaced object key."""
        return f"{tenant_id}/{case_id}/{evidence_id}/{filename}"

    # ── Upload ──────────────────────────────────────────────────

    def upload_raw_evidence(
        self,
        tenant_id: str,
        case_id: str,
        evidence_id: str,
        filename: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Upload original evidence to MinIO (immutable raw evidence bucket).
        Returns the object key for storage in PostgreSQL evidence table.
        Enforces immutability: fails closed if object already exists.
        Attaches tenant/case/evidence/SHA-256 metadata.
        """
        key = self._object_key(tenant_id, case_id, evidence_id, f"original/{filename}")
        if self.object_exists(self.RAW_BUCKET, key):
            raise RuntimeError(
                f"Immutability violation: Evidence object '{key}' already exists in '{self.RAW_BUCKET}' and cannot be overwritten."
            )

        import hashlib
        meta = {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "sha256": hashlib.sha256(data).hexdigest(),
            "filename": filename,
        }
        if metadata:
            meta.update(metadata)

        self.client.put_object(
            bucket_name=self.RAW_BUCKET,
            object_name=key,
            data=io.BytesIO(data),
            length=len(data),
            content_type=content_type,
            metadata=meta,
        )
        return key

    def upload_encrypted_evidence(
        self,
        tenant_id: str,
        case_id: str,
        evidence_id: str,
        filename: str,
        encrypted_data: bytes,
        metadata: Optional[dict] = None,
    ) -> str:
        """Upload encrypted evidence blob to the encrypted bucket."""
        key = self._object_key(
            tenant_id, case_id, evidence_id, f"encrypted/{filename}.enc"
        )
        if self.object_exists(self.ENCRYPTED_BUCKET, key):
            raise RuntimeError(
                f"Immutability violation: Encrypted evidence object '{key}' already exists in '{self.ENCRYPTED_BUCKET}' and cannot be overwritten."
            )

        import hashlib
        meta = {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "sha256": hashlib.sha256(encrypted_data).hexdigest(),
            "filename": filename,
        }
        if metadata:
            meta.update(metadata)

        self.client.put_object(
            bucket_name=self.ENCRYPTED_BUCKET,
            object_name=key,
            data=io.BytesIO(encrypted_data),
            length=len(encrypted_data),
            content_type="application/octet-stream",
            metadata=meta,
        )
        return key

    # ── Download ────────────────────────────────────────────────

    def download_raw_evidence(self, object_key: str, expected_sha256: Optional[str] = None) -> bytes:
        """Download raw evidence by its object key, with optional SHA-256 integrity assertion."""
        import hashlib
        response = self.client.get_object(self.RAW_BUCKET, object_key)
        try:
            data = response.read()
        finally:
            response.close()
            response.release_conn()

        if expected_sha256:
            actual_sha256 = hashlib.sha256(data).hexdigest()
            if actual_sha256.lower() != expected_sha256.lower():
                raise RuntimeError(
                    f"Evidence integrity violation: SHA-256 mismatch for object '{object_key}'. "
                    f"Expected {expected_sha256}, calculated {actual_sha256}"
                )
        return data

    def download_encrypted_evidence(self, object_key: str) -> bytes:
        """Download encrypted evidence blob."""
        response = self.client.get_object(self.ENCRYPTED_BUCKET, object_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    # ── Metadata ────────────────────────────────────────────────

    def get_object_stat(self, bucket: str, object_key: str) -> dict:
        """Get metadata (size, etag, last modified, user metadata) for an object."""
        stat = self.client.stat_object(bucket, object_key)
        return {
            "size": stat.size,
            "etag": stat.etag,
            "last_modified": stat.last_modified,
            "content_type": stat.content_type,
            "metadata": stat.metadata,
        }

    def object_exists(self, bucket: str, object_key: str) -> bool:
        """Check whether an object exists (non-destructive)."""
        try:
            self.client.stat_object(bucket, object_key)
            return True
        except S3Error as e:
            if e.code in ("NoSuchKey", "NotFound"):
                return False
            raise
        except Exception:
            return False

    # ── Presigned URLs (for analyst download in review UI) ──────

    def presigned_download_url(
        self, bucket: str, object_key: str, expires_seconds: int = 3600
    ) -> str:
        """Generate a time-limited presigned URL for analyst download."""
        from datetime import timedelta
        return self.client.presigned_get_object(
            bucket_name=bucket,
            object_name=object_key,
            expires=timedelta(seconds=expires_seconds),
        )


# Singleton instance
minio_store = MinioClient()
