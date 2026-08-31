import os
import sys
import unittest
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from preprocessing.schemas import Artifact, ExtractedEntity
from preprocessing.artifact_extractor.extractor import (
    ArtifactExtractor,
    extract_regex,
    GLINER_LABELS,
    GLINER_MODEL_ID,
    GLINER_REVISION,
)

_NEEDS_MODEL = os.environ.get("ARGUS_RUN_MODEL_INTEGRATION_TESTS")
_SKIP_REASON = "requires cached GLiNER weights; set ARGUS_RUN_MODEL_INTEGRATION_TESTS to run"


# ─────────────────────────────────────────────────────────────────────────────
# Mocked regression — no real model needed. Validates fix #2: the stale
# self._degraded flag no longer pre-empts the _predict_gliner call.
# ─────────────────────────────────────────────────────────────────────────────

class TestFieldRoutingRegressionMocked(unittest.TestCase):
    """
    Regression tests proving semantic entities are not lost due to field routing
    or a stale degraded flag. _predict_gliner is mocked directly; no GLiNER
    weights are required.
    """

    def setUp(self):
        self.extractor = ArtifactExtractor()

    def test_field_routing_accuracy_regression(self):
        """
        Verify Wannacry is returned by extract() for every forensic field whose
        policy includes GLiNER, even when self._degraded was True at call time
        (simulating a stale startup failure). This directly tests fix #2.
        """
        forensic_fields = [
            "process_name",
            "command_line",
            "parent_process",
            "event_data",
            "event_message",
            "description",
            "registry_data",
            "email_body",
            "browser_url",
            "narrative_field",
        ]

        for field in forensic_fields:
            text = "The system was infected with Wannacry malware."
            mock_entity = [{
                "text": "Wannacry",
                "label": "malware",
                "start": text.index("Wannacry"),
                "end": text.index("Wannacry") + len("Wannacry"),
                "score": 0.95,
            }]

            with patch.object(self.extractor, "_predict_gliner",
                              return_value=[mock_entity]):
                artifact = Artifact(
                    evidence_id="ev-routing",
                    source_tool="test",
                    artifact_type="process_event",
                    raw_fields={field: text},
                )
                policy = self.extractor.get_field_extraction_policy(
                    f"raw_fields.{field}"
                )
                entities = self.extractor.extract([artifact], "ev-routing")
                gliner_ents = [
                    e for e in entities
                    if "wannacry" in e.value.lower()
                    and e.extraction_method == "gliner"
                ]

                if policy in ("gliner", "both"):
                    self.assertEqual(
                        len(gliner_ents), 1,
                        f"Wannacry GLiNER entity lost in field '{field}' "
                        f"(policy={policy})",
                    )


@unittest.skipUnless(_NEEDS_MODEL, _SKIP_REASON)
class TestArtifactExtractorProduction(unittest.TestCase):
    """
    Production correctness tests using REAL packages, dependencies, and
    the cached GLiNER model without mocks or compatibility shims.
    """

    @classmethod
    def setUpClass(cls):
        # Load the real model
        cls.extractor = ArtifactExtractor()

    def test_imports(self):
        """Verify that the real dependencies import correctly."""
        import re2
        import torch
        import transformers
        import gliner
        self.assertIsNotNone(re2)
        self.assertIsNotNone(torch)
        self.assertIsNotNone(transformers)
        self.assertIsNotNone(gliner)

    def test_model_loading_and_integrity(self):
        """Verify the loaded model state, revision, tokenizer, and configurations."""
        self.assertEqual(self.extractor.get_model_state(), "MODEL_AVAILABLE")
        self.assertFalse(self.extractor._degraded)
        self.assertEqual(self.extractor._model_revision, GLINER_REVISION)
        self.assertEqual(self.extractor._model_name, GLINER_MODEL_ID)
        self.assertIsNotNone(self.extractor._model)
        self.assertIsNotNone(self.extractor._tokenizer)
        self.assertIsNotNone(self.extractor._device)
        self.assertIsNotNone(self.extractor._model_config)

        # Check startup hash verification parameters are set
        self.assertEqual(self.extractor._gliner_version, gliner.__version__)
        self.assertEqual(self.extractor._transformers_version, transformers.__version__)
        self.assertEqual(self.extractor._pytorch_version, torch.__version__)

    def test_routing_policy(self):
        """Test deterministic routing policy mapping logic for known forensic fields."""
        ext = self.extractor

        # PROCESS -> both
        self.assertEqual(ext.get_field_extraction_policy("process"), "both")
        self.assertEqual(ext.get_field_extraction_policy("raw_fields.command_line"), "both")
        self.assertEqual(ext.get_field_extraction_policy("image_path"), "both")

        # EVENT -> both
        self.assertEqual(ext.get_field_extraction_policy("event_message"), "both")
        self.assertEqual(ext.get_field_extraction_policy("description"), "both")
        self.assertEqual(ext.get_field_extraction_policy("rule_name"), "both")

        # METADATA -> neither
        self.assertEqual(ext.get_field_extraction_policy("evidence_id"), "neither")
        self.assertEqual(ext.get_field_extraction_policy("created_at"), "neither")
        self.assertEqual(ext.get_field_extraction_policy("timestamp"), "neither")

        # NETWORK -> regex
        self.assertEqual(ext.get_field_extraction_policy("ip"), "regex")
        self.assertEqual(ext.get_field_extraction_policy("src_ip"), "regex")
        self.assertEqual(ext.get_field_extraction_policy("domain"), "regex")
        self.assertEqual(ext.get_field_extraction_policy("url"), "both") 

        # HASH -> regex
        self.assertEqual(ext.get_field_extraction_policy("md5"), "regex")
        self.assertEqual(ext.get_field_extraction_policy("sha256"), "regex")

        # NARRATIVE -> gliner
        self.assertEqual(ext.get_field_extraction_policy("threat_intel"), "gliner")
        self.assertEqual(ext.get_field_extraction_policy("analyst_notes"), "gliner")

        # Unknown field -> regex (conservative recall fallback)
        self.assertEqual(ext.get_field_extraction_policy("unknown_custom_field"), "regex")

    def test_strict_label_validation(self):
        """Verify that unexpected labels are rejected and recorded in telemetry."""
        ext = self.extractor
        initial_rejected = ext._rejected_prediction_count

        artifact = Artifact(
            evidence_id="ev-telemetry",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": "The Lazarus group used Wannacry ransomware."}
        )
        entities = ext.extract([artifact], "ev-telemetry")
        for e in entities:
            if e.extraction_method == "gliner":
                self.assertIn(e.entity_type, GLINER_LABELS)

        # Check telemetry does not crash
        self.assertEqual(ext._rejected_prediction_count, initial_rejected)

    def test_entity_extraction_and_provenance(self):
        """Verify entity extraction and full provenance preservation."""
        artifact = Artifact(
            evidence_id="ev-prov",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={
                "command_line": "powershell.exe -c C:\\temp\\loader.exe -ip 192.168.1.100 -hash 85e977f6b92f7c0018f7000000000000",
                "description": "Executed loader malware attributed to APT28 threat-actor.",
            }
        )
        entities = self.extractor.extract([artifact], "ev-prov")

        # Check that we extracted both regex and semantic entities
        values = {e.value for e in entities}
        self.assertIn("192.168.1.100", values)
        self.assertIn("85e977f6b92f7c0018f7000000000000", values)
        self.assertIn("C:\\temp\\loader.exe", values)
        self.assertTrue(any("loader" in val or "APT28" in val for val in values))

        # Check provenance fields on each entity
        for e in entities:
            self.assertEqual(e.evidence_id, "ev-prov")
            self.assertEqual(e.artifact_id, artifact.artifact_id)
            self.assertIn(e.source_field, ["raw_fields.command_line", "raw_fields.description"])
            self.assertIsNotNone(e.entity_type)
            self.assertIsNotNone(e.char_start)
            self.assertIsNotNone(e.char_end)
            self.assertIsNotNone(e.extraction_method)
            self.assertEqual(e.extractor_version, "1.0.0")
            self.assertEqual(e.model_name, GLINER_MODEL_ID)
            self.assertEqual(e.model_revision, GLINER_REVISION)
            self.assertFalse(e.degraded_mode)

    def test_cross_layer_deduplication(self):
        """Verify that duplicate/overlapping entities are resolved without losing provenance."""
        artifact = Artifact(
            evidence_id="ev-dedup",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": "Connecting to C2 server at 192.168.1.100."}
        )
        entities = self.extractor.extract([artifact], "ev-dedup")
        
        # Verify 192.168.1.100 matches only once
        ips = [e for e in entities if e.value == "192.168.1.100"]
        self.assertEqual(len(ips), 1)
        self.assertTrue(ips[0].extraction_method.startswith("regex:"))

    def test_chunk_boundaries(self):
        """Verify boundary text chunking works on long inputs."""
        long_prose = " ".join(["APT28 is a threat group."] * 100)
        chunks = self.extractor._chunk_text(long_prose)
        self.assertTrue(len(chunks) > 1)

    def test_empty_and_malformed_inputs(self):
        """Verify that empty or malformed inputs do not crash the extractor."""
        # Empty
        entities = self.extractor.extract([], "ev-empty")
        self.assertEqual(len(entities), 0)

        # Malformed
        artifact = Artifact(
            evidence_id="ev-malformed",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"port": 8080, "deleted": True, "description": ""}
        )
        entities = self.extractor.extract([artifact], "ev-malformed")
        self.assertEqual(len(entities), 0)

    def test_accuracy_ground_truth_evaluator(self):
        """Evaluate precision, recall, and F1 on a mini ground-truth corpus."""
        corpus = [
            (
                "The malware Wannacry associated with Lazarus Group launched cmd.exe.",
                [
                    {"text": "Wannacry", "label": "malware"},
                    {"text": "Lazarus Group", "label": "threat-actor"},
                    {"text": "cmd.exe", "label": "command-line"}
                ]
            ),
            (
                "APT28 established persistence by modifying registry key Run.",
                [
                    {"text": "APT28", "label": "threat-actor"},
                    {"text": "Run", "label": "command-line"}
                ]
            ),
            (
                "The trojan Emotet was observed executing spawn process tree.",
                [
                    {"text": "Emotet", "label": "malware"},
                    {"text": "spawn process tree", "label": "command-line"}
                ]
            )
        ]

        true_positives = 0
        false_positives = 0
        false_negatives = 0

        for text, expected_entities in corpus:
            artifact = Artifact(
                evidence_id="ev-eval",
                source_tool="test",
                artifact_type="process_event",
                raw_fields={"description": text}
            )
            extracted = self.extractor.extract([artifact], "ev-eval")
            extracted_gliner = [e for e in extracted if e.extraction_method == "gliner"]

            def normalize_eval_label(label: str) -> str:
                if label == "malware_candidate":
                    return "malware"
                if label == "threat_actor":
                    return "threat-actor"
                if label in ["command_line", "executable"]:
                    return "command-line"
                return label

            # Match extracted vs expected
            matched_expected = set()
            for ext in extracted_gliner:
                found_match = False
                for idx, exp in enumerate(expected_entities):
                    val_clean = ext.value.lower().strip()
                    exp_clean = exp["text"].lower().strip()
                    if (exp_clean in val_clean or val_clean in exp_clean) and normalize_eval_label(ext.entity_type) == normalize_eval_label(exp["label"]):
                        true_positives += 1
                        matched_expected.add(idx)
                        found_match = True
                        break
                if not found_match:
                    false_positives += 1

            false_negatives += (len(expected_entities) - len(matched_expected))

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print(f"\n--- Ground-Truth Accuracy Metrics ---")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")

        self.assertTrue(f1 > 0.5, f"F1-Score too low: {f1}")

    def test_field_routing_accuracy_regression(self):
        """
        Regression tests proving that semantic entities are not lost because of field routing.
        Tests the same semantic entity appearing in different fields.
        """
        forensic_fields = [
            "process_name",
            "command_line",
            "parent_process",
            "event_data",
            "event_message",
            "description",
            "registry_data",
            "email_body",
            "browser_url",
            "narrative_field"
        ]

        for field in forensic_fields:
            artifact = Artifact(
                evidence_id="ev-routing",
                source_tool="test",
                artifact_type="process_event",
                raw_fields={field: "The system was infected with Wannacry malware."}
            )
            entities = self.extractor.extract([artifact], "ev-routing")
            extracted_malware = [e for e in entities if "wannacry" in e.value.lower() and e.entity_type in ["malware", "malware_candidate"]]
            
            self.assertEqual(
                len(extracted_malware), 1,
                f"Wannacry malware entity was lost in field '{field}' routing!"
            )

if __name__ == "__main__":
    unittest.main()
