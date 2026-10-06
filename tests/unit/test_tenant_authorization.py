import pytest
from fastapi import HTTPException

from api.routes.auth import require_authorized_tenant


def test_tenant_header_must_match_authenticated_membership():
    user = {"id": "user-a", "tenant_id": "tenant-a"}
    assert require_authorized_tenant("tenant-a", user) == "tenant-a"
    with pytest.raises(HTTPException) as error:
        require_authorized_tenant("tenant-b", user)
    assert error.value.status_code == 403


def test_legacy_user_without_membership_cannot_select_non_default_tenant():
    user = {"id": "legacy-user"}
    with pytest.raises(HTTPException) as error:
        require_authorized_tenant("default", user)
    assert error.value.status_code == 403
    with pytest.raises(HTTPException):
        require_authorized_tenant("tenant-b", user)
