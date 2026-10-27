"""
ARGUS Case Locking Service
===========================
Ensures that when one analyst opens a case for investigation, another analyst cannot
simultaneously investigate or modify the same case. Provides clear lock ownership,
heartbeat renewals, auto-expiration (TTL), and read-only access enforcement.
"""

from __future__ import annotations

import threading
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Default lock expiration without heartbeat: 10 minutes
DEFAULT_LOCK_TTL_SECONDS = 600


class CaseLock:
    def __init__(
        self,
        case_id: str,
        locked_by_user_id: str,
        locked_by_user_name: str,
        locked_by_user_email: Optional[str] = None,
        ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
        lock_token: Optional[str] = None
    ):
        self.case_id = str(case_id)
        self.locked_by_user_id = str(locked_by_user_id)
        self.locked_by_user_name = str(locked_by_user_name or locked_by_user_id)
        self.locked_by_user_email = str(locked_by_user_email) if locked_by_user_email else ""
        self.locked_at = datetime.now(timezone.utc)
        self.last_heartbeat = self.locked_at
        self.ttl_seconds = ttl_seconds
        self.expires_at = self.locked_at + timedelta(seconds=ttl_seconds)
        self.lock_token = lock_token or str(uuid.uuid4())

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def refresh(self, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        now = datetime.now(timezone.utc)
        self.last_heartbeat = now
        self.expires_at = now + timedelta(seconds=ttl)

    def to_dict(self, current_user_id: Optional[str] = None) -> Dict[str, Any]:
        user_id_str = str(current_user_id or "")
        is_owner = bool(user_id_str and user_id_str == self.locked_by_user_id)
        return {
            "case_id": self.case_id,
            "is_locked": not self.is_expired(),
            "is_owner": is_owner,
            "read_only": not is_owner,
            "lock_token": self.lock_token if is_owner else None,
            "locked_by": {
                "id": self.locked_by_user_id,
                "name": self.locked_by_user_name,
                "email": self.locked_by_user_email
            },
            "locked_at": self.locked_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "time_remaining_seconds": max(0, int((self.expires_at - datetime.now(timezone.utc)).total_seconds()))
        }


class CaseLockManager:
    """Thread-safe in-memory case lock repository with TTL and heartbeat validation."""

    def __init__(self):
        self._locks: Dict[str, CaseLock] = {}
        self._lock = threading.RLock()

    def clean_expired_locks(self) -> None:
        with self._lock:
            expired_keys = [cid for cid, lk in self._locks.items() if lk.is_expired()]
            for cid in expired_keys:
                del self._locks[cid]

    def get_lock(self, case_id: str) -> Optional[CaseLock]:
        with self._lock:
            cid = str(case_id)
            lock = self._locks.get(cid)
            if lock:
                if lock.is_expired():
                    del self._locks[cid]
                    return None
                return lock
            return None

    def acquire_or_refresh(
        self,
        case_id: str,
        user_id: str,
        user_name: str,
        user_email: Optional[str] = None,
        ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS
    ) -> Tuple[bool, CaseLock, str]:
        """
        Attempts to acquire a case lock for `user_id`.
        Returns:
            (is_granted: bool, lock: CaseLock, status_code: str)
            status_code can be 'ACQUIRED', 'REFRESHED', or 'LOCKED_BY_OTHER'
        """
        with self._lock:
            cid = str(case_id)
            uid = str(user_id)
            existing = self.get_lock(cid)

            # 1. No active lock or lock expired -> acquire
            if not existing:
                new_lock = CaseLock(
                    case_id=cid,
                    locked_by_user_id=uid,
                    locked_by_user_name=user_name,
                    locked_by_user_email=user_email,
                    ttl_seconds=ttl_seconds
                )
                self._locks[cid] = new_lock
                logger.info(f"[CASE LOCK] Acquired lock for case '{cid}' by user '{user_name}' ({uid})")
                return True, new_lock, "ACQUIRED"

            # 2. Existing lock owned by SAME analyst -> refresh
            if existing.locked_by_user_id == uid:
                existing.refresh(ttl_seconds)
                # Update display name if changed
                if user_name:
                    existing.locked_by_user_name = user_name
                if user_email:
                    existing.locked_by_user_email = user_email
                logger.debug(f"[CASE LOCK] Refreshed lock for case '{cid}' by user '{user_name}' ({uid})")
                return True, existing, "REFRESHED"

            # 3. Existing lock owned by ANOTHER analyst -> lock denied, read-only
            logger.warning(
                f"[CASE LOCK CONFLICT] User '{user_name}' ({uid}) attempted to acquire case '{cid}', "
                f"which is locked by '{existing.locked_by_user_name}' ({existing.locked_by_user_id})"
            )
            return False, existing, "LOCKED_BY_OTHER"

    def heartbeat(self, case_id: str, user_id: str, ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS) -> Tuple[bool, Optional[CaseLock], str]:
        with self._lock:
            cid = str(case_id)
            uid = str(user_id)
            existing = self.get_lock(cid)

            if not existing:
                return False, None, "NO_LOCK"

            if existing.locked_by_user_id != uid:
                return False, existing, "NOT_OWNER"

            existing.refresh(ttl_seconds)
            return True, existing, "HEARTBEAT_ACK"

    def release(self, case_id: str, user_id: str, is_admin: bool = False) -> Tuple[bool, str]:
        with self._lock:
            cid = str(case_id)
            uid = str(user_id)
            existing = self.get_lock(cid)

            if not existing:
                return True, "NO_ACTIVE_LOCK"

            if existing.locked_by_user_id == uid or is_admin:
                del self._locks[cid]
                logger.info(f"[CASE LOCK] Released lock on case '{cid}' by user '{uid}' (admin={is_admin})")
                return True, "RELEASED"

            return False, "NOT_AUTHORIZED"

    def check_modification_allowed(self, case_id: str, user_id: str, is_admin: bool = False) -> Tuple[bool, Optional[CaseLock], str]:
        """
        Validates if `user_id` is permitted to modify or investigate `case_id`.
        Returns:
            (allowed: bool, lock: Optional[CaseLock], message: str)
        """
        with self._lock:
            cid = str(case_id)
            uid = str(user_id)
            existing = self.get_lock(cid)

            # If no active lock, auto-grant (or could auto-acquire)
            if not existing:
                return True, None, "UNLOCKED"

            if existing.locked_by_user_id == uid or is_admin:
                return True, existing, "OWNER"

            return False, existing, (
                f"Case '{cid}' is currently locked for investigation by analyst "
                f"'{existing.locked_by_user_name}'. You have Read-Only access."
            )

    def get_all_active_locks(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            self.clean_expired_locks()
            return {cid: lk.to_dict() for cid, lk in self._locks.items()}


# Global singleton instance
case_lock_manager = CaseLockManager()
