from pathlib import Path

import pytest

from infrastructure.repository import evidence_store


def test_repository_destination_rejects_traversal():
    with pytest.raises(ValueError):
        evidence_store._safe_repository_destination(
            "..\\outside", "E-1", "evidence.bin"
        )
    with pytest.raises(ValueError):
        evidence_store._safe_repository_destination(
            "C-1", "E-1", "..\\outside.bin"
        )


def test_repository_destination_stays_under_root(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence_store, "REPOSITORY_DIR", str(tmp_path))
    original, encrypted = evidence_store._safe_repository_destination(
        "C-1", "E-1", "evidence.bin"
    )
    assert original.is_relative_to(tmp_path.resolve())
    assert encrypted.is_relative_to(tmp_path.resolve())
