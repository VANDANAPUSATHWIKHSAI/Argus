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
    ) -> str:
        """
        Upload original evidence to MinIO (immutable raw evidence bucket).
        Returns the object key for storage in PostgreSQL evidence table.
        """
        key = self._object_key(tenant_id, case_id, evidence_id, f"original/{filename}")
        self.client.put_object(
            bucket_name=self.RAW_BUCKET,
            object_name=key,
            data=io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )
        return key

    def upload_encrypted_evidence(
        self,
        tenant_id: str,
        case_id: str,
        evidence_id: str,
        filename: str,
        encrypted_data: bytes,
    ) -> str:
        """Upload encrypted evidence blob to the encrypted bucket."""
        key = self._object_key(
            tenant_id, case_id, evidence_id, f"encrypted/{filename}.enc"
        )
        self.client.put_object(
            bucket_name=self.ENCRYPTED_BUCKET,
            object_name=key,
            data=io.BytesIO(encrypted_data),
            length=len(encrypted_data),
            content_type="application/octet-stream",
        )
        return key

    # ── Download ────────────────────────────────────────────────

    def download_raw_evidence(self, object_key: str) -> bytes:
        """Download raw evidence by its object key."""
        response = self.client.get_object(self.RAW_BUCKET, object_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

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
        """Get metadata (size, etag, last modified) for an object."""
        stat = self.client.stat_object(bucket, object_key)
        return {
            "size": stat.size,
            "etag": stat.etag,
            "last_modified": stat.last_modified,
            "content_type": stat.content_type,
        }

    def object_exists(self, bucket: str, object_key: str) -> bool:
        """Check whether an object exists (non-destructive)."""
        try:
            self.client.stat_object(bucket, object_key)
            return True
        except S3Error as e:
            if e.code == "NoSuchKey":
                return False
            raise

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
