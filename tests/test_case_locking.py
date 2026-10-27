import pytest
import time
from datetime import datetime, timezone, timedelta
from api.case_lock import CaseLock, CaseLockManager

def test_case_lock_lifecycle():
    manager = CaseLockManager()
    case_id = "CASE-101"

    # 1. Analyst 1 acquires lock
    granted, lock, code = manager.acquire_or_refresh(
        case_id=case_id,
        user_id="user_analyst_1",
        user_name="Sarah Analyst",
        user_email="sarah@argus.local",
        ttl_seconds=300
    )
    assert granted is True
    assert code == "ACQUIRED"
    assert lock.locked_by_user_id == "user_analyst_1"
    assert lock.locked_by_user_name == "Sarah Analyst"
    assert lock.is_expired() is False

    # Check lock dict for owner vs non-owner
    owner_view = lock.to_dict(current_user_id="user_analyst_1")
    assert owner_view["is_locked"] is True
    assert owner_view["is_owner"] is True
    assert owner_view["read_only"] is False

    other_view = lock.to_dict(current_user_id="user_analyst_2")
    assert other_view["is_locked"] is True
    assert other_view["is_owner"] is False
    assert other_view["read_only"] is True
    assert other_view["locked_by"]["name"] == "Sarah Analyst"

    # 2. Analyst 2 attempts to acquire the same case -> Denied, Read-Only
    granted2, lock2, code2 = manager.acquire_or_refresh(
        case_id=case_id,
        user_id="user_analyst_2",
        user_name="David Forensics",
        user_email="david@argus.local",
        ttl_seconds=300
    )
    assert granted2 is False
    assert code2 == "LOCKED_BY_OTHER"
    assert lock2.locked_by_user_id == "user_analyst_1"

    # Check modification permissions
    allowed_owner, _, _ = manager.check_modification_allowed(case_id, "user_analyst_1")
    assert allowed_owner is True

    allowed_other, _, msg = manager.check_modification_allowed(case_id, "user_analyst_2")
    assert allowed_other is False
    assert "Sarah Analyst" in msg
    assert "Read-Only" in msg

    # Admin is allowed to modify / override
    allowed_admin, _, _ = manager.check_modification_allowed(case_id, "admin_user", is_admin=True)
    assert allowed_admin is True

    # 3. Heartbeat from Analyst 2 is rejected
    hb_ok, hb_lock, hb_code = manager.heartbeat(case_id, "user_analyst_2")
    assert hb_ok is False
    assert hb_code == "NOT_OWNER"

    # Heartbeat from Analyst 1 succeeds
    hb_ok1, hb_lock1, hb_code1 = manager.heartbeat(case_id, "user_analyst_1", ttl_seconds=600)
    assert hb_ok1 is True
    assert hb_code1 == "HEARTBEAT_ACK"

    # 4. Analyst 1 releases lock
    rel_ok, rel_msg = manager.release(case_id, "user_analyst_1")
    assert rel_ok is True
    assert rel_msg == "RELEASED"

    # Now case is unlocked
    assert manager.get_lock(case_id) is None
    allowed_now, _, _ = manager.check_modification_allowed(case_id, "user_analyst_2")
    assert allowed_now is True

    # 5. Analyst 2 can now acquire lock
    granted3, lock3, code3 = manager.acquire_or_refresh(
        case_id=case_id,
        user_id="user_analyst_2",
        user_name="David Forensics",
        ttl_seconds=300
    )
    assert granted3 is True
    assert code3 == "ACQUIRED"
    assert lock3.locked_by_user_id == "user_analyst_2"


def test_stale_lock_expiration():
    manager = CaseLockManager()
    case_id = "CASE-STALE"

    # Create a lock that is already expired
    lock = CaseLock(
        case_id=case_id,
        locked_by_user_id="user_stale",
        locked_by_user_name="Inactive Analyst",
        ttl_seconds=-10  # negative ttl -> expired immediately
    )
    manager._locks[case_id] = lock

    # Querying lock should detect expiration and clean it up
    assert manager.get_lock(case_id) is None

    # Another analyst should be able to acquire immediately
    granted, new_lock, code = manager.acquire_or_refresh(
        case_id=case_id,
        user_id="user_active",
        user_name="Active Analyst",
        ttl_seconds=300
    )
    assert granted is True
    assert code == "ACQUIRED"
    assert new_lock.locked_by_user_id == "user_active"
