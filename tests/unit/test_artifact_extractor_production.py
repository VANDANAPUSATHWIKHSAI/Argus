"""
Targeted tests for Preprocessing Artifact Extractor Audit and Repair.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.artifact_extractor.resolver import ProcessRelationshipResolver

class TestArtifactExtractorProductionTargeted(unittest.TestCase):

    def setUp(self):
        self.ext = ArtifactExtractor()

    def test_production_extractor_source_contains_no_magicmock(self):
        # 1. Production extractor source contains no MagicMock import/use.
        import preprocessing.artifact_extractor.extractor as extractor
        source_path = extractor.__file__
        with open(source_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("MagicMock", content)
        self.assertNotIn("unittest.mock", content)

    def test_production_extractor_does_not_instantiate_magicmock(self):
        # 2. Production extractor does not instantiate MagicMock.
        with patch("preprocessing.artifact_extractor.extractor.pipeline") as mock_pipeline:
            mock_pipeline.return_value = lambda x: []
            with patch("transformers.AutoModelForTokenClassification.from_pretrained") as mock_model, \
                 patch("transformers.AutoTokenizer.from_pretrained") as mock_tok, \
                 patch("huggingface_hub.hf_hub_download") as mock_download:
                model_inst = MagicMock()
                if hasattr(model_inst, "predict_entities"):
                    del model_inst.predict_entities
                mock_model.return_value = model_inst
                mock_tok.return_value = MagicMock()
                mock_download.return_value = __file__
                
                mock_hash = MagicMock()
                mock_hash.hexdigest.side_effect = [
                    "097d42dda461f69ed32bbc99a59c3175ec5626b80280aca5eef10996d73308fa",
                    "fb0341635cf5a236eaff5bf77728c563a000f8ce846abf314808c1448bf612ed",
                    "9313554f1d10f9e6addc02ea82c727f7e646d9cfb153d2cb62560b9268dd4ca4",
                    "bbdee0f89bf77971bc593224c513496e4ec34aecc199b60e64d2b45ac7aa61ff",
                    "c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd",
                    "a4b6bfe668f2b3cf6f0cd535e98a0663d2d0d4a4a15f13075ad3597d33985a23",
                    "b70b72bbc44ed96ae896e1b26d2d269d40a58709c9de1428c9bbfa872fe7f7ce"
                ]
                
                with patch("hashlib.sha256", return_value=mock_hash):
                    ext = ArtifactExtractor()
                    self.assertNotIsInstance(ext._pipeline, MagicMock)

    def test_real_extractor_path_is_selected(self):
        # 3. Real extractor path is selected.
        with patch("preprocessing.artifact_extractor.extractor.pipeline") as mock_pipeline:
            mock_pipeline.return_value = lambda text: [
                {"entity_group": "threat_group", "word": "APT28", "start": 0, "end": 5, "score": 0.95}
            ]
            with patch("transformers.AutoModelForTokenClassification.from_pretrained") as mock_model, \
                 patch("transformers.AutoTokenizer.from_pretrained") as mock_tok, \
                 patch("huggingface_hub.hf_hub_download") as mock_download:
                model_inst = MagicMock()
                if hasattr(model_inst, "predict_entities"):
                    del model_inst.predict_entities
                mock_model.return_value = model_inst
                mock_tok.return_value = MagicMock()
                mock_download.return_value = __file__
                
                mock_hash = MagicMock()
                mock_hash.hexdigest.side_effect = [
                    "097d42dda461f69ed32bbc99a59c3175ec5626b80280aca5eef10996d73308fa",
                    "fb0341635cf5a236eaff5bf77728c563a000f8ce846abf314808c1448bf612ed",
                    "9313554f1d10f9e6addc02ea82c727f7e646d9cfb153d2cb62560b9268dd4ca4",
                    "bbdee0f89bf77971bc593224c513496e4ec34aecc199b60e64d2b45ac7aa61ff",
                    "c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd",
                    "a4b6bfe668f2b3cf6f0cd535e98a0663d2d0d4a4a15f13075ad3597d33985a23",
                    "b70b72bbc44ed96ae896e1b26d2d269d40a58709c9de1428c9bbfa872fe7f7ce"
                ]
                
                with patch("hashlib.sha256", return_value=mock_hash):
                    ext = ArtifactExtractor()
                    res = ext._predict_gliner(["APT28 is a threat group."])
                    self.assertIsNotNone(res)
                    self.assertEqual(res[0][0]["text"], "APT28")
                    self.assertEqual(res[0][0]["label"], "threat-actor")

    def test_ip_and_port_overlap_resolution(self):
        # IP:port overlap resolution (192.168.1.1 and 192.168.1.1:8080)
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="network_connection",
            raw_fields={"connection": "Initiated traffic to 192.168.1.1:8080"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        # Verify we get the IP 192.168.1.1, and not two duplicate IP spans for it
        ip_ents = [e for e in extracted if e.entity_type == "ipv4"]
        self.assertEqual(len(ip_ents), 1)
        self.assertEqual(ip_ents[0].value, "192.168.1.1")

    def test_ipv6_and_port(self):
        # IPv6 and IPv6 with port
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="network_connection",
            raw_fields={"connection": "IPv6 session [2001:db8::1]:443"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        ipv6_ents = [e for e in extracted if e.entity_type == "ipv6"]
        self.assertEqual(len(ipv6_ents), 1)
        self.assertEqual(ipv6_ents[0].value, "2001:db8::1")

    def test_url_and_domain_fqdn_extraction(self):
        # URL and nested Domain/FQDN
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="network_flow",
            raw_fields={"url": "Visit http://malicious.example.com/payload.exe"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        url_ents = [e for e in extracted if e.entity_type == "url"]
        domain_ents = [e for e in extracted if e.entity_type == "domain"]
        
        # Legitimate overlapping different types must BOTH be kept
        self.assertEqual(len(url_ents), 1)
        self.assertEqual(url_ents[0].value, "http://malicious.example.com/payload.exe")
        self.assertEqual(len(domain_ents), 1)
        self.assertEqual(domain_ents[0].value, "malicious.example.com")

    def test_hash_nesting_suppression(self):
        # MD5 nested inside SHA256 must be suppressed
        sha256_val = "9313554f1d10f9e6addc02ea82c727f7e646d9cfb153d2cb62560b9268dd4ca4"
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="file_record",
            raw_fields={"hash": f"SHA256: {sha256_val}"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        sha256_ents = [e for e in extracted if e.entity_type == "sha256"]
        md5_ents = [e for e in extracted if e.entity_type == "md5"]
        
        self.assertEqual(len(sha256_ents), 1)
        self.assertEqual(sha256_ents[0].value, sha256_val)
        # Nested MD5 is suppressed because same family overlap
        self.assertEqual(len(md5_ents), 0)

    def test_windows_unc_linux_paths(self):
        # Windows file path, UNC path, Linux path
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={
                "description": "Executed C:\\Windows\\System32\\cmd.exe with share \\\\server\\share\\file.txt on Linux path /var/log/auth.log"
            }
        )
        extracted = self.ext.extract([art], "ev1")
        
        paths = {e.value for e in extracted if e.entity_type == "file_path"}
        self.assertIn("C:\\Windows\\System32\\cmd.exe", paths)
        self.assertIn("\\\\server\\share\\file.txt", paths)
        self.assertIn("/var/log/auth.log", paths)

    def test_quoted_paths_and_paths_containing_spaces(self):
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={
                "description": 'Launched "C:\\Program Files\\App\\bin.exe" or unquoted C:\\Windows\\My Folder\\temp.exe'
            }
        )
        extracted = self.ext.extract([art], "ev1")
        
        paths = {e.value for e in extracted if e.entity_type == "file_path"}
        self.assertIn("C:\\Program Files\\App\\bin.exe", paths)
        self.assertIn("C:\\Windows\\My Folder\\temp.exe", paths)

    def test_registry_key_extraction(self):
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="registry_key",
            raw_fields={"key": "Created key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        reg_ents = [e for e in extracted if e.entity_type == "registry_key"]
        self.assertEqual(len(reg_ents), 1)
        self.assertEqual(reg_ents[0].value, "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")

    def test_email_extraction(self):
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="email_header",
            raw_fields={"from": "attacker@baddomain.com"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        email_ents = [e for e in extracted if e.entity_type == "email"]
        self.assertEqual(len(email_ents), 1)
        self.assertEqual(email_ents[0].value, "attacker@baddomain.com")

    def test_command_line_and_executable_nesting(self):
        # Command-line and nested executable path resolution
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\script.ps1"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        cmd_ents = [e for e in extracted if e.entity_type == "command_line"]
        exec_ents = [e for e in extracted if e.entity_type == "executable"]
        
        # Legitimate different overlapping types must BOTH be kept
        self.assertEqual(len(cmd_ents), 1)
        self.assertEqual(cmd_ents[0].value, "powershell.exe -ExecutionPolicy Bypass -File C:\\script.ps1")
        self.assertEqual(len(exec_ents), 1)
        self.assertEqual(exec_ents[0].value, "powershell.exe")

    def test_process_and_process_tree_linkage(self):
        # Process and parent relationship data
        art1 = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            normalized_fields=NormalizedFields(
                host="SOC-WORKSTATION",
                user="admin",
                process_id=1200,
                parent_process_id=800,
                process_name="explorer.exe",
                process_command_line="explorer.exe /factory"
            )
        )
        art2 = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            normalized_fields=NormalizedFields(
                host="SOC-WORKSTATION",
                user="admin",
                process_id=1500,
                parent_process_id=1200,
                process_name="cmd.exe",
                process_command_line="cmd.exe /c whoami"
            )
        )
        
        extracted = self.ext.extract([art1, art2], "ev1")
        
        # Verify that process metadata fields are extracted
        pids = {e.value for e in extracted if e.entity_type == "process_id"}
        ppids = {e.value for e in extracted if e.entity_type == "parent_process_id"}
        names = {e.value for e in extracted if e.entity_type in ("process_name", "system_process")}
        
        self.assertIn("1200", pids)
        self.assertIn("1500", pids)
        self.assertIn("800", ppids)
        self.assertIn("1200", ppids)
        self.assertIn("explorer.exe", names)
        self.assertIn("cmd.exe", names)
        
        # Verify ProcessRelationshipResolver matches them
        resolver = ProcessRelationshipResolver()
        relations = resolver.resolve_relationships([art1, art2])
        
        self.assertEqual(len(relations), 1)
        rel = relations[0]
        self.assertEqual(rel["parent"]["pid"], 1200)
        self.assertEqual(rel["parent"]["process_name"], "explorer.exe")
        self.assertEqual(rel["child"]["pid"], 1500)
        self.assertEqual(rel["child"]["process_name"], "cmd.exe")
        self.assertEqual(rel["relationship"], "SPAWNS")

    def test_usb_extraction(self):
        # Specialized USB serial/device extraction
        art = Artifact(
            evidence_id="ev1",
            source_tool="regripper",
            artifact_type="usb_device",
            raw_fields={
                "device_id": "USB\\VID_0930&PID_6545\\00123456789",
                "drive_letter": "E:",
                "vendor_product": "Toshiba TransMemory"
            },
            normalized_fields=NormalizedFields(
                usb_serial_number="00123456789"
            )
        )
        extracted = self.ext.extract([art], "ev1")
        
        serial_ents = [e for e in extracted if e.entity_type == "usb_serial_number"]
        dev_id_ents = [e for e in extracted if e.entity_type == "device_identifier"]
        drive_ents = [e for e in extracted if e.entity_type == "drive_letter"]
        vp_ents = [e for e in extracted if e.entity_type == "vendor_product_info"]
        
        self.assertEqual(len(serial_ents), 1)
        self.assertEqual(serial_ents[0].value, "00123456789")
        self.assertEqual(len(dev_id_ents), 1)
        self.assertEqual(dev_id_ents[0].value, "USB\\VID_0930&PID_6545\\00123456789")
        self.assertEqual(len(drive_ents), 1)
        self.assertEqual(drive_ents[0].value, "E:")
        self.assertEqual(len(vp_ents), 1)
        self.assertEqual(vp_ents[0].value, "Toshiba TransMemory")

    def test_provenance_and_immutability(self):
        # Provenance preservation and raw evidence immutability
        art = Artifact(
            case_id="case-999",
            evidence_id="ev-888",
            source_tool="hayabusa",
            artifact_type="process_event",
            raw_fields={
                "ip": "8.8.8.8",
                "byte_offset": 512,
                "line_number": 42
            }
        )
        extracted = self.ext.extract([art], "ev-888")
        
        self.assertGreaterEqual(len(extracted), 1)
        ent = extracted[0]
        
        self.assertEqual(ent.artifact_id, art.artifact_id)
        self.assertEqual(ent.case_id, "case-999")
        self.assertEqual(ent.evidence_id, "ev-888")
        self.assertEqual(ent.source_tool, "hayabusa")
        self.assertEqual(ent.byte_offset, 512)
        self.assertEqual(ent.line_number, 42)
        self.assertEqual(ent.original_value, "8.8.8.8")
        
        # Verify immutability (Artifact properties and raw_fields remain unmodified)
        self.assertEqual(art.case_id, "case-999")
        self.assertEqual(art.raw_fields["ip"], "8.8.8.8")
        self.assertEqual(art.raw_fields["byte_offset"], 512)

    def test_degraded_confidence_metadata(self):
        # Verify metadata extraction in degraded vs non-degraded
        self.ext._degraded = True
        self.ext._degraded_reason = "HF offline"
        
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="network_connection",
            raw_fields={"ip": "1.1.1.1"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        ent = extracted[0]
        self.assertTrue(ent.degraded_mode)
        self.assertEqual(ent.degraded_reason, "HF offline")
        self.assertEqual(ent.extraction_method, "regex:ipv4")

    def test_missing_model_failsafe_behavior(self):
        # Offline token loading failure sets degraded mode
        with patch("transformers.AutoTokenizer.from_pretrained", side_effect=Exception("Model files not found")):
            ext = ArtifactExtractor()
            self.assertTrue(ext._degraded)
            self.assertEqual(ext.get_model_state(), "MODEL_UNAVAILABLE")

    def test_duplicate_nested_suppression(self):
        # Duplicate entities same type/value suppressed
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"desc": "Connection to 8.8.8.8 and 8.8.8.8"}
        )
        extracted = self.ext.extract([art], "ev1")
        
        ip_ents = [e for e in extracted if e.entity_type == "ipv4"]
        # Only one entity should remain due to deduplication
        self.assertEqual(len(ip_ents), 1)

    def test_deterministic_behavior(self):
        # Repeated extraction yields exact same results
        art = Artifact(
            evidence_id="ev1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"desc": "Run cmd.exe on HKLM\\Software\\Run"}
        )
        
        first = self.ext.extract([art], "ev1")
        second = self.ext.extract([art], "ev1")
        
        self.assertEqual(len(first), len(second))
        for i in range(len(first)):
            self.assertEqual(first[i].entity_type, second[i].entity_type)
            self.assertEqual(first[i].value, second[i].value)
            self.assertEqual(first[i].char_start, second[i].char_start)
            self.assertEqual(first[i].char_end, second[i].char_end)

if __name__ == "__main__":
    unittest.main()
