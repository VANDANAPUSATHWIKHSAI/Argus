"""
Unit Tests for DpapiVaultParser & Router Integration
=====================================================
Tests parsing of DPAPI / Credential Manager / Windows Vault evidence:
- Masterkey files (PREFERRED)
- Windows Credential Manager blobs
- Windows Vault records (.vcrd / .vpol)
- Raw DPAPI protected blobs
- Protection flags and provenance
- Error handling and router integration
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.dpapi_parser import (
    DpapiVaultParser,
    DpapiVaultNotFoundError,
    DpapiVaultParserError,
    DPAPI_BLOB_HEADER_BYTES,
)


class TestDpapiVaultParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = DpapiVaultParser()
        self.router = ParserRouter()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # 1. Masterkey PREFERRED file parsing
    def test_parse_masterkey_preferred(self) -> None:
        file_path = self.temp_path / "Microsoft" / "Protect" / "S-1-5-21-123456789-987654321-1001" / "PREFERRED"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("{31b2f340-016d-11d2-945f-00c04fb984f9}\n", encoding="ascii")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-dpapi-001")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "dpapi_vault_parser")
        self.assertEqual(art.artifact_type, "credential_metadata")
        self.assertEqual(art.raw_fields["masterkey_guid"], "{31b2f340-016d-11d2-945F-00c04fb984f9}".lower())
        self.assertEqual(art.raw_fields["owner_sid"], "S-1-5-21-123456789-987654321-1001")
        self.assertFalse(art.raw_fields["decrypted"])
        self.assertTrue(art.raw_fields["is_protected"])

    # 2. Windows Credential File Parsing
    def test_parse_credential_file(self) -> None:
        cred_dir = self.temp_path / "AppData" / "Roaming" / "Microsoft" / "Credentials"
        cred_dir.mkdir(parents=True, exist_ok=True)
        file_path = cred_dir / "53B980D1234567890ABCDEF123456789"

        # Construct payload with target name and user name in UTF-16LE
        target = "targetname:git:https://github.com".encode("utf-16le") + b"\x00\x00"
        user = "domain\\analyst".encode("utf-16le") + b"\x00\x00"
        file_bytes = b"\x01\x00\x00\x00" + b"\x00" * 12 + (132000000000000000).to_bytes(8, "little") + target + user
        file_path.write_bytes(file_bytes)

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-dpapi-002")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "dpapi_vault_parser")
        self.assertEqual(art.artifact_type, "credential_metadata")
        self.assertFalse(art.raw_fields["decrypted"])
        self.assertTrue(art.raw_fields["is_protected"])

    # 3. Windows Vault Record Parsing
    def test_parse_vault_file(self) -> None:
        vault_dir = self.temp_path / "AppData" / "Local" / "Microsoft" / "Vault" / "{12345678-1234-1234-1234-1234567890AB}"
        vault_dir.mkdir(parents=True, exist_ok=True)
        file_path = vault_dir / "Policy.vpol"

        content = b"VAULT_POLICY_{12345678-1234-1234-1234-1234567890AB}\x00\x00" + "Web Credentials".encode("utf-16le")
        file_path.write_bytes(content)

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-dpapi-003")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "dpapi_vault_parser")
        self.assertFalse(art.raw_fields["decrypted"])
        self.assertTrue(art.raw_fields["is_protected"])

    # 4. Raw DPAPI Protected Data Blob Parsing
    def test_parse_dpapi_blob_signature(self) -> None:
        # Header (20 bytes) + GUID (16 bytes) + AlgIDs (8 bytes) + Salt/Data payload
        guid_bytes = uuid.UUID("{31b2f340-016d-11d2-945f-00c04fb984f9}").bytes_le
        blob_bytes = DPAPI_BLOB_HEADER_BYTES + guid_bytes + (0x6611).to_bytes(4, "little") + (0x800e).to_bytes(4, "little") + b"\x00" * 32
        file_path = self.temp_path / "dpapi_data.bin"
        file_path.write_bytes(blob_bytes)

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-dpapi-004")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.raw_fields["blob_header"], "DPAPI_BLOB")
        self.assertEqual(art.raw_fields["masterkey_guid"], "31b2f340-016d-11d2-945f-00c04fb984f9")
        self.assertEqual(art.raw_fields["cipher_algorithm"], "AES-256")
        self.assertEqual(art.raw_fields["hash_algorithm"], "SHA-256")
        self.assertFalse(art.raw_fields["decrypted"])
        self.assertTrue(art.raw_fields["is_protected"])

    # 5. JSON Credential Export Parsing
    def test_parse_json_export(self) -> None:
        json_content = (
            "[\n"
            "  {\n"
            "    \"Target\": \"WindowsLive:User=analyst@corp.local\",\n"
            "    \"Username\": \"analyst@corp.local\",\n"
            "    \"MasterKeyGUID\": \"{31b2f340-016d-11d2-945f-00c04fb984f9}\",\n"
            "    \"decrypted\": false\n"
            "  }\n"
            "]\n"
        )
        file_path = self.temp_path / "credentials.json"
        file_path.write_text(json_content, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-dpapi-005")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.raw_fields["Target"], "WindowsLive:User=analyst@corp.local")
        self.assertEqual(art.normalized_fields.user, "analyst@corp.local")

    # 6. Error Handling — Missing File
    def test_error_handling_not_found(self) -> None:
        missing_path = str(self.temp_path / "non_existent.cred")
        with self.assertRaises(DpapiVaultNotFoundError):
            self.parser.parse(missing_path)

    # 7. Error Handling — Empty File
    def test_error_handling_empty_file(self) -> None:
        empty_path = self.temp_path / "empty.cred"
        empty_path.write_text("", encoding="utf-8")
        with self.assertRaises(DpapiVaultParserError):
            self.parser.parse(str(empty_path))

    # 8. Router Integration Tests
    def test_router_integration_masterkey_preferred(self) -> None:
        file_path = self.temp_path / "Microsoft" / "Protect" / "S-1-5-21-100" / "PREFERRED"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("{31b2f340-016d-11d2-945f-00c04fb984f9}\n", encoding="ascii")

        ev = Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-r-dpapi-01",
            filename="PREFERRED",
            file_path=str(file_path),
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "DpapiVaultParser")
        self.assertIsInstance(self.router.route(ev), DpapiVaultParser)

    def test_router_integration_dpapi_blob_signature(self) -> None:
        blob_file = self.temp_path / "secret.bin"
        blob_file.write_bytes(DPAPI_BLOB_HEADER_BYTES + b"\x00" * 32)

        ev = Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-r-dpapi-02",
            filename="secret.bin",
            file_path=str(blob_file),
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "DpapiVaultParser")
        self.assertEqual(res.detection_method, "signature")


if __name__ == "__main__":
    unittest.main()
