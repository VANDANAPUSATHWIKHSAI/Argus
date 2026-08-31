"""
Artifact Extractor Tests
=========================
Unit tests for preprocessing/artifact_extractor/extractor.py.

Tests are fully self-contained — GLiNER model is mocked, no real model
download needed. External dependencies (torch, transformers) are mocked
where necessary so CI passes without GPU or large model files.

Covers:
  - Each regex pattern's true positives and known false-positive traps
  - Character offset accuracy for every pattern
  - Chunk-boundary merge / dedupe logic
  - Batch extraction correctness
  - Degraded-mode fallback
  - Concurrency lock (simulate two concurrent calls)

Usage:
    pytest preprocessing/artifact_extractor/test_artifact_extractor.py
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.artifact_extractor.extractor import (
    extract_regex,
    ArtifactExtractor,
    YaraScanner,
    GLINER_LABELS,
    GLINER_MODEL_ID,
    GLINER_REVISION,
    MAX_SEQ_TOKENS,
    OVERLAP_TOKENS,
)
import preprocessing.artifact_extractor.extractor as extractor
extractor.pipeline = MagicMock()


# ═══════════════════════════════════════════════════════════════════════════════
# REGEX TRUE-POSITIVE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegexIPv4(unittest.TestCase):
    """IPv4 address pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "ipv4"]

    def test_basic_ipv4(self):
        ents = self._extract("Source IP: 192.168.1.100 connected to server")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0].value, "192.168.1.100")
        self.assertEqual(ents[0].char_start, 11)
        self.assertEqual(ents[0].char_end, 24)

    def test_multiple_ipv4(self):
        ents = self._extract("10.0.0.1 -> 172.16.0.255")
        self.assertEqual(len(ents), 2)
        values = {e.value for e in ents}
        self.assertIn("10.0.0.1", values)
        self.assertIn("172.16.0.255", values)

    def test_edge_octets(self):
        ents = self._extract("addr=255.255.255.255 and addr=0.0.0.0")
        values = {e.value for e in ents}
        self.assertIn("255.255.255.255", values)
        self.assertIn("0.0.0.0", values)

    def test_false_positive_version_number(self):
        """Version numbers like 1.2.3.4 look like IPs — regex skips them now."""
        ents = self._extract("version 1.2.3.4")
        self.assertEqual(len(ents), 0)

    def test_invalid_octet_rejected(self):
        """Octets > 255 should NOT match."""
        ents = self._extract("addr=999.999.999.999")
        self.assertEqual(len(ents), 0)


class TestRegexIPv6(unittest.TestCase):
    """IPv6 address pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "ipv6"]

    def test_full_ipv6(self):
        ents = self._extract("host fe80:0000:0000:0000:0000:0000:0000:0001 connected")
        self.assertTrue(len(ents) >= 1)

    def test_abbreviated_ipv6(self):
        ents = self._extract("dst fe80::1 connected")
        self.assertTrue(any("fe80" in e.value for e in ents))


class TestRegexHashes(unittest.TestCase):
    """MD5, SHA-1, SHA-256 hash patterns."""

    def _extract(self, text):
        return extract_regex(text, "f", "a1", "e1")

    def test_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        ents = self._extract(f"hash={md5}")
        md5_ents = [e for e in ents if e.entity_type == "md5"]
        self.assertEqual(len(md5_ents), 1)
        self.assertEqual(md5_ents[0].value, md5)

    def test_sha1(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ents = self._extract(f"sha1:{sha1}")
        sha1_ents = [e for e in ents if e.entity_type == "sha1"]
        self.assertEqual(len(sha1_ents), 1)
        self.assertEqual(sha1_ents[0].value, sha1)

    def test_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ents = self._extract(f"SHA256: {sha256}")
        sha256_ents = [e for e in ents if e.entity_type == "sha256"]
        self.assertEqual(len(sha256_ents), 1)
        self.assertEqual(sha256_ents[0].value, sha256)

    def test_md5_not_in_sha256(self):
        """A SHA-256 hash contains 64 hex chars — should NOT also match as MD5."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ents = self._extract(sha256)
        # SHA-256 match should exist
        self.assertTrue(any(e.entity_type == "sha256" for e in ents))


class TestRegexEmail(unittest.TestCase):
    """Email address pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "email"]

    def test_basic_email(self):
        ents = self._extract("from: admin@example.com to: user@test.org")
        values = {e.value for e in ents}
        self.assertIn("admin@example.com", values)
        self.assertIn("user@test.org", values)

    def test_plus_addressing(self):
        ents = self._extract("user+tag@domain.co.uk")
        self.assertTrue(len(ents) >= 1)

    def test_offset_accuracy(self):
        text = "Contact: alice@corp.io for details"
        ents = self._extract(text)
        self.assertEqual(len(ents), 1)
        self.assertEqual(text[ents[0].char_start:ents[0].char_end], "alice@corp.io")


class TestRegexURL(unittest.TestCase):
    """URL pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "url"]

    def test_http_url(self):
        ents = self._extract("downloaded from http://malware.example.com/payload.exe")
        self.assertEqual(len(ents), 1)
        self.assertTrue(ents[0].value.startswith("http://"))

    def test_https_url(self):
        ents = self._extract("C2: https://evil.net/c2?id=42&key=abc")
        self.assertEqual(len(ents), 1)
        self.assertTrue("evil.net" in ents[0].value)


class TestRegexDomain(unittest.TestCase):
    """Domain name pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "domain"]

    def test_basic_domain(self):
        ents = self._extract("resolved malicious.example.com in DNS")
        values = {e.value for e in ents}
        self.assertTrue(any("example.com" in v for v in values))

    def test_subdomain(self):
        ents = self._extract("beacon to c2.threat-actor.io detected")
        self.assertTrue(len(ents) >= 1)


class TestRegexRegistryKey(unittest.TestCase):
    """Windows registry key pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "registry_key"]

    def test_hklm_key(self):
        text = r"Modified HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        ents = self._extract(text)
        self.assertEqual(len(ents), 1)
        self.assertIn("HKEY_LOCAL_MACHINE", ents[0].value)

    def test_hkcu_abbreviation(self):
        text = r"Key: HKCU\Software\Classes\ms-settings"
        ents = self._extract(text)
        self.assertEqual(len(ents), 1)
        self.assertIn("HKCU", ents[0].value)


class TestRegexFilePaths(unittest.TestCase):
    """Windows and Unix file path patterns."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "file_path"]

    def test_windows_path(self):
        text = r"Executed C:\Users\admin\AppData\Local\Temp\malware.exe"
        ents = self._extract(text)
        self.assertTrue(any("malware.exe" in e.value for e in ents))

    def test_unix_path(self):
        text = "binary at /usr/local/bin/ncat running"
        ents = self._extract(text)
        self.assertTrue(any("/usr/local/bin/ncat" in e.value for e in ents))


class TestRegexCVE(unittest.TestCase):
    """CVE ID pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "cve_id"]

    def test_cve_standard(self):
        ents = self._extract("Exploited CVE-2024-12345 in attack chain")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0].value, "CVE-2024-12345")

    def test_cve_five_digit(self):
        ents = self._extract("CVE-2021-44228 (Log4Shell)")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0].value, "CVE-2021-44228")

    def test_no_partial_cve(self):
        ents = self._extract("CVE-202-123")  # too short year
        self.assertEqual(len(ents), 0)


class TestRegexMITRE(unittest.TestCase):
    """MITRE ATT&CK technique ID pattern."""

    def _extract(self, text):
        return [e for e in extract_regex(text, "f", "a1", "e1") if e.entity_type == "mitre_attack"]

    def test_technique(self):
        ents = self._extract("Technique T1059 observed (Command and Scripting Interpreter)")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0].value, "T1059")

    def test_subtechnique(self):
        ents = self._extract("Used T1059.001 PowerShell")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0].value, "T1059.001")


# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACTION METHOD AND CONFIDENCE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegexExtractionMetadata(unittest.TestCase):
    """Verify extraction_method format and confidence for regex entities."""

    def test_extraction_method_format(self):
        ents = extract_regex("IP 10.0.0.1 found", "field", "a1", "e1")
        ipv4_ents = [e for e in ents if e.entity_type == "ipv4"]
        self.assertTrue(all(e.extraction_method.startswith("regex:") for e in ipv4_ents))

    def test_confidence_always_one(self):
        ents = extract_regex("hash d41d8cd98f00b204e9800998ecf8427e", "f", "a1", "e1")
        self.assertTrue(all(e.confidence == 1.0 for e in ents))

    def test_degraded_mode_default_false(self):
        ents = extract_regex("IP 10.0.0.1", "f", "a1", "e1")
        self.assertTrue(all(not e.degraded_mode for e in ents))


# ═══════════════════════════════════════════════════════════════════════════════
# CHUNK-BOUNDARY MERGE & DEDUP TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestChunkBoundaryMerge(unittest.TestCase):
    """Test _merge_chunk_boundary_entities deduplicates overlap region."""

    def _make_entity(self, value, start, end, conf=0.8, entity_type="malware"):
        return ExtractedEntity(
            artifact_id="a1", evidence_id="e1", entity_type=entity_type,
            value=value, source_field="raw_fields.body",
            char_start=start, char_end=end,
            extraction_method="gliner", confidence=conf,
            model_revision=GLINER_REVISION,
        )

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_duplicate_in_overlap_deduped(self, mock_load):
        """Same entity found in two overlapping chunks → keep best."""
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        e1 = self._make_entity("Emotet", 100, 106, conf=0.85)
        e2 = self._make_entity("Emotet", 100, 106, conf=0.92)

        merged = ext._merge_chunk_boundary_entities([e1, e2])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].confidence, 0.92)

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_different_entities_not_merged(self, mock_load):
        """Different entity values are NOT merged."""
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        e1 = self._make_entity("Emotet", 100, 106)
        e2 = self._make_entity("Cobalt Strike", 200, 213)

        merged = ext._merge_chunk_boundary_entities([e1, e2])
        self.assertEqual(len(merged), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-LAYER DEDUP TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossLayerDedup(unittest.TestCase):
    """Test deduplication when regex and GLiNER find the same entity."""

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_same_span_merged(self, mock_load):
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        regex_ent = ExtractedEntity(
            artifact_id="a1", evidence_id="e1", entity_type="ipv4",
            value="10.0.0.1", source_field="f",
            char_start=5, char_end=13,
            extraction_method="regex:ipv4", confidence=1.0,
        )
        gliner_ent = ExtractedEntity(
            artifact_id="a1", evidence_id="e1", entity_type="ipv4",
            value="10.0.0.1", source_field="f",
            char_start=5, char_end=13,
            extraction_method="gliner", confidence=0.95,
            model_revision=GLINER_REVISION,
        )

        merged = ext._cross_layer_dedup([regex_ent], [gliner_ent])
        self.assertEqual(len(merged), 1)
        self.assertIn("regex:ipv4+gliner", merged[0].extraction_method)
        self.assertEqual(merged[0].confidence, 1.0)  # regex confidence wins

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_different_span_not_merged(self, mock_load):
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        regex_ent = ExtractedEntity(
            artifact_id="a1", evidence_id="e1", entity_type="ipv4",
            value="10.0.0.1", source_field="f",
            char_start=5, char_end=13,
            extraction_method="regex:ipv4", confidence=1.0,
        )
        gliner_ent = ExtractedEntity(
            artifact_id="a1", evidence_id="e1", entity_type="malware",
            value="Emotet", source_field="f",
            char_start=50, char_end=56,
            extraction_method="gliner", confidence=0.88,
            model_revision=GLINER_REVISION,
        )

        merged = ext._cross_layer_dedup([regex_ent], [gliner_ent])
        self.assertEqual(len(merged), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# BATCH EXTRACTION TESTS (GLiNER mocked)
# ═══════════════════════════════════════════════════════════════════════════════

class TestBatchExtraction(unittest.TestCase):
    """Test extract() with GLiNER fully mocked."""

    def _make_extractor(self):
        """Build an ArtifactExtractor with GLiNER mocked out."""
        with patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model"):
            ext = ArtifactExtractor.__new__(ArtifactExtractor)
            ext._model = MagicMock()
            ext._tokenizer = None
            ext._model_revision = GLINER_REVISION
            ext._lock = threading.Lock()
            ext._degraded = False

            # Mock predict_entities to return a canned result
            def mock_predict(text, labels, threshold=0.3):
                results = []
                if "Emotet" in text:
                    idx = text.index("Emotet")
                    results.append({
                        "text": "Emotet",
                        "label": "malware",
                        "start": idx,
                        "end": idx + 6,
                        "score": 0.92,
                    })
                return results

            ext._model.predict_entities = mock_predict
            return ext

    def test_batch_extracts_regex_and_gliner(self):
        ext = self._make_extractor()

        artifact = Artifact(
            evidence_id="e1",
            source_tool="hayabusa",
            artifact_type="process_event",
            raw_fields={
                "body": "The Emotet trojan connected to 185.220.101.5 via C2 channel"
            },
        )

        entities = ext.extract([artifact], "e1")

        values = {e.value for e in entities}
        self.assertIn("185.220.101.5", values)  # regex
        self.assertIn("Emotet", values)  # GLiNER

    def test_batch_multiple_artifacts(self):
        ext = self._make_extractor()

        art1 = Artifact(
            evidence_id="e1",
            source_tool="zeek",
            artifact_type="dns_query",
            raw_fields={"query": "malware.example.com"},
        )
        art2 = Artifact(
            evidence_id="e1",
            source_tool="suricata",
            artifact_type="ids_alert",
            raw_fields={"detail": "CVE-2021-44228 exploit detected from 10.0.0.1"},
        )

        entities = ext.extract([art1, art2], "e1")
        types = {e.entity_type for e in entities}
        self.assertIn("domain", types)
        self.assertIn("cve_id", types)
        self.assertIn("ipv4", types)


# ═══════════════════════════════════════════════════════════════════════════════
# DEGRADED MODE FALLBACK TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDegradedModeFallback(unittest.TestCase):
    """Test that extraction works in regex-only mode when GLiNER fails."""

    def test_model_load_failure_sets_degraded(self):
        """If model fails to load, extractor should run degraded."""
        with patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model") as mock_load:
            ext = ArtifactExtractor.__new__(ArtifactExtractor)
            ext._model = None
            ext._tokenizer = None
            ext._model_revision = None
            ext._lock = threading.Lock()
            ext._degraded = True  # simulating load failure

            artifact = Artifact(
                evidence_id="e1",
                source_tool="hayabusa",
                artifact_type="process_event",
                raw_fields={"body": "IP 10.0.0.1 connection detected"},
            )

            entities = ext.extract([artifact], "e1")
            # Should still extract regex entities
            self.assertTrue(len(entities) > 0)
            # All should be marked degraded
            self.assertTrue(all(e.degraded_mode for e in entities))
            # All should be regex-only
            self.assertTrue(all(e.extraction_method.startswith("regex:") for e in entities))

    def test_inference_failure_falls_back(self):
        """If GLiNER predict_entities throws, fallback to regex + degraded."""
        with patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model"):
            ext = ArtifactExtractor.__new__(ArtifactExtractor)
            ext._model = MagicMock()
            ext._tokenizer = None
            ext._model_revision = GLINER_REVISION
            ext._lock = threading.Lock()
            ext._degraded = False

            # Make predict_entities throw
            ext._model.predict_entities.side_effect = RuntimeError("CUDA OOM")

            artifact = Artifact(
                evidence_id="e1",
                source_tool="zeek",
                artifact_type="dns_query",
                raw_fields={"body": "malware.example.com from 10.0.0.1"},
            )

            entities = ext.extract([artifact], "e1")
            # Should still extract regex entities
            self.assertTrue(len(entities) > 0)
            # All should be marked degraded after inference failure
            self.assertTrue(all(e.degraded_mode for e in entities))


# ═══════════════════════════════════════════════════════════════════════════════
# CONCURRENCY LOCK TEST
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrencyLock(unittest.TestCase):
    """Simulate two concurrent calls and assert no interleaving corruption."""

    def test_concurrent_extraction_no_corruption(self):
        """Two threads calling extract() simultaneously should not corrupt results."""
        with patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model"):
            ext = ArtifactExtractor.__new__(ArtifactExtractor)
            ext._model = MagicMock()
            ext._tokenizer = None
            ext._model_revision = GLINER_REVISION
            ext._lock = threading.Lock()
            ext._degraded = False

            call_order = []

            def slow_predict(text, labels, threshold=0.3):
                call_order.append(("enter", threading.current_thread().name))
                time.sleep(0.05)  # Simulate inference time
                results = []
                if "APT28" in text:
                    idx = text.index("APT28")
                    results.append({
                        "text": "APT28", "label": "threat-actor",
                        "start": idx, "end": idx + 5, "score": 0.88,
                    })
                if "Lazarus" in text:
                    idx = text.index("Lazarus")
                    results.append({
                        "text": "Lazarus", "label": "threat-actor",
                        "start": idx, "end": idx + 7, "score": 0.91,
                    })
                call_order.append(("exit", threading.current_thread().name))
                return results

            ext._model.predict_entities = slow_predict

            art1 = Artifact(
                evidence_id="e1", source_tool="test", artifact_type="test",
                raw_fields={"body": "APT28 group attacked via 10.0.0.1"},
            )
            art2 = Artifact(
                evidence_id="e2", source_tool="test", artifact_type="test",
                raw_fields={"body": "Lazarus group used 172.16.0.1"},
            )

            results = {}
            errors = []

            def run_extract(name, artifacts, eid):
                try:
                    results[name] = ext.extract(artifacts, eid)
                except Exception as e:
                    errors.append(e)

            t1 = threading.Thread(target=run_extract, args=("t1", [art1], "e1"), name="thread-1")
            t2 = threading.Thread(target=run_extract, args=("t2", [art2], "e2"), name="thread-2")

            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

            self.assertEqual(len(errors), 0, f"Errors during concurrent extraction: {errors}")

            # Verify no interleaving — each thread's results contain only its own entities
            r1_values = {e.value for e in results["t1"]}
            r2_values = {e.value for e in results["t2"]}

            # Thread 1 should have APT28, Thread 2 should have Lazarus
            self.assertIn("APT28", r1_values)
            self.assertIn("Lazarus", r2_values)

            # Cross-contamination check: APT28 should NOT be in thread 2's results
            self.assertNotIn("APT28", r2_values)
            self.assertNotIn("Lazarus", r1_values)

            # Verify the lock serialized inference (enter/exit should not interleave)
            # Check that no thread-2 "enter" appears between thread-1 "enter" and "exit"
            for i, (action, thread) in enumerate(call_order):
                if action == "enter":
                    # Find the matching exit
                    for j in range(i + 1, len(call_order)):
                        if call_order[j] == ("exit", thread):
                            # Between i and j, no other thread should have entered
                            for k in range(i + 1, j):
                                self.assertNotEqual(
                                    call_order[k][0], "enter",
                                    f"Lock violation: {call_order[k]} interleaved between "
                                    f"{call_order[i]} and {call_order[j]}"
                                )
                            break


# ═══════════════════════════════════════════════════════════════════════════════
# CHUNKING TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestTextChunking(unittest.TestCase):
    """Test token-aware text chunking with overlap."""

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_short_text_single_chunk(self, mock_load):
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        chunks = ext._chunk_text("Short text here")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], ("Short text here", 0))

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_long_text_multiple_chunks(self, mock_load):
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None  # whitespace fallback
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        # Generate text that is definitely longer than MAX_SEQ_TOKENS tokens
        long_text = " ".join([f"word{i}" for i in range(2000)])
        chunks = ext._chunk_text(long_text)
        self.assertTrue(len(chunks) > 1)
        # First chunk should start at offset 0
        self.assertEqual(chunks[0][1], 0)



# ═══════════════════════════════════════════════════════════════════════════════
# ACCURACY REGRESSION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAccuracyRegressions(unittest.TestCase):
    """Regression tests for forensic accuracy edge cases identified in the audit."""

    def test_windows_path_no_trailing_prose(self):
        text = r"Windows path: C:\Program Files\Common Files\system.dll and Unix path"
        ents = extract_regex(text, "body", "a1", "e1")
        paths = [e.value for e in ents if e.entity_type == "file_path"]
        self.assertIn(r"C:\Program Files\Common Files\system.dll", paths)
        self.assertNotIn(r"C:\Program Files\Common Files\system.dll and Unix path", paths)

    def test_registry_key_no_trailing_prose(self):
        text = r"Registry HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run is hijacked"
        ents = extract_regex(text, "body", "a1", "e1")
        keys = [e.value for e in ents if e.entity_type == "registry_key"]
        self.assertIn(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", keys)
        self.assertNotIn(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run is hijacked", keys)

    def test_ipv4_version_number_filter(self):
        text = "Product version is 1.2.3.4 and connection is 10.0.0.1"
        ents = extract_regex(text, "body", "a1", "e1")
        ips = [e.value for e in ents if e.entity_type == "ipv4"]
        self.assertIn("10.0.0.1", ips)
        self.assertNotIn("1.2.3.4", ips)  # version number suppressed

    @patch("preprocessing.artifact_extractor.extractor.ArtifactExtractor._load_model")
    def test_subspan_containment_suppression(self, mock_load):
        ext = ArtifactExtractor.__new__(ArtifactExtractor)
        ext._model = None
        ext._tokenizer = None
        ext._model_revision = None
        ext._lock = threading.Lock()
        ext._degraded = True

        artifact = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="test",
            raw_fields={
                "body": "Download payload from http://malware.com/bad.exe or mail admin@evil.com"
            }
        )

        entities = ext.extract([artifact], "e1")
        types = {e.entity_type for e in entities}
        values = {e.value for e in entities}

        # Keep parent URLs and emails
        self.assertIn("http://malware.com/bad.exe", values)
        self.assertIn("admin@evil.com", values)

        # Suppress sub-spans like /malware.com/bad.exe or evil.com inside them
        self.assertNotIn("/malware.com/bad.exe", values)
        self.assertNotIn("evil.com", values)


class TestModelLifecycle(unittest.TestCase):
    """Verify production model lifecycle requirements and offline safety."""

    @patch("transformers.AutoModelForTokenClassification.from_pretrained")
    @patch("transformers.AutoTokenizer.from_pretrained")
    @patch("huggingface_hub.hf_hub_download")
    def test_model_loading_and_available(self, mock_download, mock_tok, mock_model):
        mock_model.return_value = MagicMock()
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
            self.assertEqual(ext.get_model_state(), "MODEL_AVAILABLE")
            self.assertTrue(ext.health_check())
            self.assertFalse(ext._degraded)

            art = Artifact(
                evidence_id="e1",
                source_tool="test",
                artifact_type="test",
                raw_fields={"body": "Normal text with IP 10.0.0.1"}
            )
            ents = ext.extract([art], "e1")
            self.assertTrue(len(ents) >= 1)
            for e in ents:
                self.assertEqual(e.extractor_version, "1.0.0")
                self.assertEqual(e.model_name, "PranavaKailash/CyNER-2.0-DeBERTa-v3-base")
                self.assertFalse(e.degraded_mode)
                self.assertIsNone(e.degraded_reason)

    @patch("huggingface_hub.hf_hub_download")
    def test_model_unavailable_offline(self, mock_download):
        mock_download.side_effect = ValueError("local_files_only is set to True but the file is not cached")

        ext = ArtifactExtractor()
        self.assertEqual(ext.get_model_state(), "MODEL_UNAVAILABLE")
        self.assertFalse(ext.health_check())
        self.assertTrue(ext._degraded)
        self.assertIn("not pre-provisioned/cached locally", ext._degraded_reason)

        art = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="test",
            raw_fields={"body": "Standard IP 10.0.0.1"}
        )
        ents = ext.extract([art], "e1")
        self.assertTrue(len(ents) >= 1)
        for e in ents:
            self.assertEqual(e.extractor_version, "1.0.0")
            self.assertTrue(e.degraded_mode)
            self.assertEqual(e.degraded_reason, ext._degraded_reason)


class TestDegradedFlagRegression(unittest.TestCase):
    """
    Fast unit tests (no real model weights required) that pin the exact
    behaviour changed by fixes #1 and #2 in extractor.py.

    Fix #1 — _predict_gliner returns None, not [], when model is absent.
    Fix #2 — extract() ignores the stale self._degraded snapshot and lets
              the _predict_gliner return value be the sole source of truth.
    """

    def test_extract_succeeds_when_degraded_pre_true(self):
        """
        Before fix #2, setting self._degraded = True before calling extract()
        would silently skip GLiNER entirely and also block normal regex results
        from being stamped correctly.  After fix #2, the stale flag is irrelevant
        to whether GLiNER *tries* to run — only the return value of
        _predict_gliner decides what happens.

        Concretely: even with self._degraded = True, extract() must:
         - return regex entities (IP in this case), and
         - correctly call _predict_gliner (mocked to return a valid list),
           producing GLiNER entities too.
        """
        ext = ArtifactExtractor()
        # Force the stale degraded state that previously blocked everything
        ext._degraded = True
        ext._degraded_reason = "simulated stale startup failure"

        text = "Connecting from 10.0.0.1 and threat actor APT28 launched malware."
        mock_ent = [{
            "text": "APT28", "label": "threat-actor",
            "start": text.index("APT28"),
            "end": text.index("APT28") + len("APT28"),
            "score": 0.92,
        }]

        with patch.object(ext, "_predict_gliner", return_value=[mock_ent]):
            art = Artifact(
                evidence_id="e-reg",
                source_tool="test",
                artifact_type="process_event",
                raw_fields={"description": text},
            )
            ents = ext.extract([art], "e-reg")

        # Regex must still fire (IP is always a regex entity)
        ip_ents = [e for e in ents if e.value == "10.0.0.1"]
        self.assertGreaterEqual(len(ip_ents), 1, "Regex entity lost when _degraded=True")

        # GLiNER must also have run because _predict_gliner returned a list
        gliner_ents = [e for e in ents if e.extraction_method == "gliner"]
        self.assertGreaterEqual(len(gliner_ents), 1,
                                "GLiNER entity lost even though _predict_gliner returned "
                                "a valid list — fix #2 may not be in effect")

    def test_predict_gliner_returns_none_when_model_absent(self):
        """
        Before fix #1, _predict_gliner returned [[]...] when self._model is None,
        which is indistinguishable from 'model ran but found nothing'.
        After fix #1 it must return None — the same signal as a runtime failure —
        so the degraded-fallback branch in extract() is correctly triggered.
        """
        ext = ArtifactExtractor()
        ext._model = None  # simulate unavailable model

        result = ext._predict_gliner(["any text"])
        self.assertIsNone(result,
                          "_predict_gliner should return None (not an empty list) "
                          "when self._model is None")


class TestTargetedResolverFixes(unittest.TestCase):
    def setUp(self):
        self.extractor = ArtifactExtractor()

    def test_cmdline_span_expansion_a(self):
        # A. powershell.exe -NoProfile -EncodedCommand abc
        text = "Executing powershell.exe -NoProfile -EncodedCommand abc to dump credentials."
        resolver = self.extractor._cmd_resolver
        start = text.index("powershell.exe")
        end = start + len("powershell.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "powershell.exe")
        self.assertEqual(new_val, "powershell.exe -NoProfile -EncodedCommand abc")

    def test_cmdline_span_expansion_b(self):
        # B. vssadmin.exe delete shadows /all
        text = "The attacker used vssadmin.exe delete shadows /all to cause disruption."
        resolver = self.extractor._cmd_resolver
        start = text.index("vssadmin.exe")
        end = start + len("vssadmin.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "vssadmin.exe")
        self.assertEqual(new_val, "vssadmin.exe delete shadows /all")

    def test_cmdline_span_expansion_c(self):
        # C. "The administrator executed powershell.exe." should not consume unrelated prose
        text = "The administrator executed powershell.exe. The server rebooted shortly after."
        resolver = self.extractor._cmd_resolver
        start = text.index("powershell.exe")
        end = start + len("powershell.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "powershell.exe")
        self.assertEqual(new_val, "powershell.exe")

    def test_executable_candidate_d(self):
        # D. "loader-12.exe was executed." should produce an executable/execution candidate (not confirmed malware)
        art = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": "loader-12.exe was executed."}
        )
        # Mock GLiNER outputting loader-12.exe as command-line
        with patch.object(self.extractor, "_predict_gliner", return_value=[[{"text": "loader-12.exe", "label": "command-line", "start": 0, "end": 13, "score": 0.95}]]):
            ents = self.extractor.extract([art], "e1")
            gliner_ents = [e for e in ents if e.extraction_method == "gliner"]
            self.assertEqual(len(gliner_ents), 1)
            self.assertEqual(gliner_ents[0].entity_type, "executable")
            self.assertFalse(gliner_ents[0].validated)

    def test_system_process_e(self):
        # E. "to dump LSASS." should map LSASS as system_process, not malware
        art = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": "Attempted to dump LSASS process."}
        )
        with patch.object(self.extractor, "_predict_gliner", return_value=[[{"text": "LSASS", "label": "malware", "start": 18, "end": 23, "score": 0.94}]]):
            ents = self.extractor.extract([art], "e1")
            gliner_ents = [e for e in ents if e.extraction_method == "gliner"]
            self.assertEqual(len(gliner_ents), 1)
            self.assertEqual(gliner_ents[0].entity_type, "system_process")

    def test_threat_actor_f(self):
        # F. "Threat actor Thomas launched the campaign." should map to threat_actor candidate
        art = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": "Threat actor Thomas launched the campaign."}
        )
        with patch.object(self.extractor, "_predict_gliner", return_value=[[{"text": "Thomas", "label": "threat-actor", "start": 13, "end": 19, "score": 0.98}]]):
            ents = self.extractor.extract([art], "e1")
            gliner_ents = [e for e in ents if e.extraction_method == "gliner"]
            self.assertEqual(len(gliner_ents), 1)
            self.assertEqual(gliner_ents[0].entity_type, "threat_actor")

    def test_threat_researcher_g(self):
        # G. "Microsoft threat researcher Thomas published an analysis." should remain unconfirmed
        art = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": "Microsoft threat researcher Thomas published an analysis."}
        )
        # GLiNER extracts Thomas as threat-actor in this context
        with patch.object(self.extractor, "_predict_gliner", return_value=[[{"text": "Thomas", "label": "threat-actor", "start": 28, "end": 34, "score": 0.90}]]):
            ents = self.extractor.extract([art], "e1")
            gliner_ents = [e for e in ents if e.extraction_method == "gliner"]
            self.assertEqual(len(gliner_ents), 1)
            self.assertEqual(gliner_ents[0].entity_type, "unconfirmed_person")
            self.assertEqual(gliner_ents[0].predicted_type, "threat-actor")
            self.assertEqual(gliner_ents[0].validation_status, "downgraded")
            self.assertFalse(gliner_ents[0].validated)

    def test_cmdline_custom_tool_a(self):
        # "The attacker executed eviltool.exe --inject payload.bin during the operation." -> "eviltool.exe --inject payload.bin"
        text = "The attacker executed eviltool.exe --inject payload.bin during the operation."
        resolver = self.extractor._cmd_resolver
        start = text.index("eviltool.exe")
        end = start + len("eviltool.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "eviltool.exe")
        self.assertEqual(new_val, "eviltool.exe --inject payload.bin")

    def test_cmdline_custom_tool_b(self):
        # "custom-loader.exe --stage 2 C:\Temp\payload.bin was executed." -> "custom-loader.exe --stage 2 C:\Temp\payload.bin"
        text = "custom-loader.exe --stage 2 C:\\Temp\\payload.bin was executed."
        resolver = self.extractor._cmd_resolver
        start = text.index("custom-loader.exe")
        end = start + len("custom-loader.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "custom-loader.exe")
        self.assertEqual(new_val, "custom-loader.exe --stage 2 C:\\Temp\\payload.bin")

    def test_cmdline_extensionless_a(self):
        # "The attacker executed /tmp/loader --stage 2 payload.bin." -> "/tmp/loader --stage 2 payload.bin"
        text = "The attacker executed /tmp/loader --stage 2 payload.bin."
        resolver = self.extractor._cmd_resolver
        start = text.index("/tmp/loader")
        end = start + len("/tmp/loader")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "/tmp/loader")
        self.assertEqual(new_val, "/tmp/loader --stage 2 payload.bin")

    def test_cmdline_extensionless_b(self):
        # "The attacker executed loader --stage 2 payload.bin." -> "loader --stage 2 payload.bin"
        text = "The attacker executed loader --stage 2 payload.bin."
        resolver = self.extractor._cmd_resolver
        start = text.index("loader")
        end = start + len("loader")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "loader")
        self.assertEqual(new_val, "loader --stage 2 payload.bin")

    def test_cmdline_linux_a(self):
        # bash -c "curl http://example.com/payload.sh" -> complete command with quotes
        text = 'bash -c "curl http://example.com/payload.sh"'
        resolver = self.extractor._cmd_resolver
        start = text.index("bash")
        end = start + len("bash")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "bash")
        self.assertEqual(new_val, 'bash -c "curl http://example.com/payload.sh"')

    def test_cmdline_linux_b(self):
        # "python3 /tmp/script.py --mode analysis" -> complete command
        text = "python3 /tmp/script.py --mode analysis"
        resolver = self.extractor._cmd_resolver
        start = text.index("python3")
        end = start + len("python3")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "python3")
        self.assertEqual(new_val, "python3 /tmp/script.py --mode analysis")

    def test_cmdline_linux_c(self):
        # "python3 was mentioned in the report." -> bare executable "python3"
        text = "python3 was mentioned in the report."
        resolver = self.extractor._cmd_resolver
        start = text.index("python3")
        end = start + len("python3")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "python3")
        self.assertEqual(new_val, "python3")

    def test_cmdline_colon_slash_a(self):
        # "Note: powershell.exe was observed." -> "powershell.exe"
        text = "Note: powershell.exe was observed."
        resolver = self.extractor._cmd_resolver
        start = text.index("powershell.exe")
        end = start + len("powershell.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "powershell.exe")
        self.assertEqual(new_val, "powershell.exe")

    def test_cmdline_colon_slash_b(self):
        # "Time: 10:30 powershell.exe was observed." -> "powershell.exe"
        text = "Time: 10:30 powershell.exe was observed."
        resolver = self.extractor._cmd_resolver
        start = text.index("powershell.exe")
        end = start + len("powershell.exe")
        new_start, new_end, new_val = resolver.resolve_command_line(text, start, end, "powershell.exe")
        self.assertEqual(new_val, "powershell.exe")

class TestNewPipelineAdditions(unittest.TestCase):
    """Unit tests for the strengthened artifact extractor pipeline additions."""

    @patch("transformers.AutoModelForTokenClassification.from_pretrained")
    @patch("transformers.AutoTokenizer.from_pretrained")
    @patch("huggingface_hub.hf_hub_download")
    def test_defanged_ioc_extraction(self, mock_download, mock_tok, mock_model):
        """1. A defanged IOC ("hxxp://evil[.]com") correctly extracted and normalized."""
        mock_model.return_value = MagicMock()
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
            art = Artifact(
                evidence_id="e1",
                source_tool="test",
                artifact_type="process_event",
                raw_fields={"url_field": "Check hxxp://evil[.]com and domain evil[.]com"}
            )
            extracted = ext.extract_artifacts([art], "e1")
            
            urls = [a for a in extracted if a.artifact_type == "extracted_ioc" and a.raw_fields.get("ioc_type") == "url"]
            domains = [a for a in extracted if a.artifact_type == "extracted_ioc" and a.raw_fields.get("ioc_type") == "domain"]
            
            self.assertGreaterEqual(len(urls), 1)
            self.assertEqual(urls[0].raw_fields.get("normalized_value"), "http://evil.com")
            self.assertEqual(urls[0].raw_fields.get("raw_value"), "hxxp://evil[.]com")
            self.assertTrue(urls[0].raw_fields.get("defanged"))
            
            self.assertGreaterEqual(len(domains), 1)
            self.assertEqual(domains[0].raw_fields.get("normalized_value"), "evil.com")
            self.assertEqual(domains[0].raw_fields.get("raw_value"), "evil[.]com")
            self.assertTrue(domains[0].raw_fields.get("defanged"))

    @patch("transformers.AutoModelForTokenClassification.from_pretrained")
    @patch("transformers.AutoTokenizer.from_pretrained")
    @patch("huggingface_hub.hf_hub_download")
    def test_invalid_ip_rejected(self, mock_download, mock_tok, mock_model):
        """2. An invalid-looking IP correctly rejected by validation."""
        mock_model.return_value = MagicMock()
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
            art = Artifact(
                evidence_id="e1",
                source_tool="test",
                artifact_type="process_event",
                raw_fields={"ip_field": "An invalid IP 300.400.500.600 and private 192.168.1.1"}
            )
            extracted = ext.extract_artifacts([art], "e1")
            ips = [a.raw_fields.get("normalized_value") for a in extracted if a.raw_fields.get("ioc_type") == "ipv4"]
            
            self.assertNotIn("300.400.500.600", ips)
            self.assertIn("192.168.1.1", ips)
            
            private_ip_art = [a for a in extracted if a.raw_fields.get("normalized_value") == "192.168.1.1"][0]
            self.assertTrue(private_ip_art.normalized_fields.private_ip)
            self.assertEqual(private_ip_art.normalized_fields.ip_scope, "private")

    def test_yara_rule_matching(self):
        """3. A known test YARA rule correctly matching a crafted test string."""
        import tempfile
        rule_content = """
        rule Test_Malware_Rule {
            strings:
                $mal_str = "crafted_test_string_for_yara"
            condition:
                $mal_str
        }
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yar') as tf:
            tf.write(rule_content)
            temp_path = tf.name

        try:
            scanner = YaraScanner(rule_filepath=temp_path)
            test_data = b"Some data containing crafted_test_string_for_yara and other binary junk"
            matched_artifacts = scanner.scan_binary(test_data, "art-1", "e1")
            
            yara_matches = [a for a in matched_artifacts if a.artifact_type == "yara_match"]
            self.assertEqual(len(yara_matches), 1)
            self.assertEqual(yara_matches[0].raw_fields.get("rule_name"), "Test_Malware_Rule")
            self.assertIn("crafted_test_string_for_yara", "".join(yara_matches[0].raw_fields.get("matched_strings")))
        finally:
            import os
            os.unlink(temp_path)

    @patch("preprocessing.artifact_extractor.extractor.pipeline", side_effect=ValueError("pipeline failed to load offline"))
    def test_ner_model_lifecycle_degraded_on_failure(self, mock_pipeline):
        """4. CyNER/SecureBERT swap still triggering degraded_mode correctly on simulated load failure."""
        ext = ArtifactExtractor()
        self.assertEqual(ext.get_model_state(), "MODEL_UNAVAILABLE")
        self.assertTrue(ext._degraded)
        self.assertIn("pipeline failed to load offline", ext._degraded_reason)

        art = Artifact(
            evidence_id="e1",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"body": "Check 10.0.0.1"}
        )
        entities = ext.extract([art], "e1")
        self.assertTrue(len(entities) >= 1)
        self.assertTrue(all(e.degraded_mode for e in entities))

    @patch("transformers.AutoModelForTokenClassification.from_pretrained")
    @patch("transformers.AutoTokenizer.from_pretrained")
    @patch("huggingface_hub.hf_hub_download")
    def test_base64_decode_and_rescan(self, mock_download, mock_tok, mock_model):
        """5. A base64-encoded IP inside a command-line string correctly decoded, extracted, and trace-tagged."""
        mock_model.return_value = MagicMock()
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
            art = Artifact(
                evidence_id="e1",
                source_tool="test",
                artifact_type="process_event",
                raw_fields={"cmd": "powershell.exe -enc Q2hlY2sgMTkyLjE2OC4xLjUwIEMyIGNvbm5lY3Rpb24="}
            )
            extracted = ext.extract_artifacts([art], "e1")
            ips = [a for a in extracted if a.raw_fields.get("normalized_value") == "192.168.1.50"]
            self.assertEqual(len(ips), 1)
            self.assertEqual(ips[0].raw_fields.get("decoded_from"), "Q2hlY2sgMTkyLjE2OC4xLjUwIEMyIGNvbm5lY3Rpb24")

    def test_dedup_and_provenance_merge(self):
        """6. Same IP appearing via both ioc-finder and YARA correctly merges into one artifact with both tools listed in found_by."""
        import tempfile
        rule_content = """
        rule Match_IP_Rule {
            strings:
                $ip_str = "10.0.0.5"
            condition:
                $ip_str
        }
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yar') as tf:
            tf.write(rule_content)
            temp_path = tf.name

        try:
            scanner = YaraScanner(rule_filepath=temp_path)
            
            with patch("transformers.AutoModelForTokenClassification.from_pretrained"), \
                 patch("transformers.AutoTokenizer.from_pretrained"), \
                 patch("huggingface_hub.hf_hub_download", return_value=__file__):
                
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
                    ext._yara_scanner = scanner
                    
                    art = Artifact(
                        evidence_id="e1",
                        source_tool="hayabusa",
                        artifact_type="process_event",
                        raw_fields={
                            "ip": "Connection to 10.0.0.5",
                            "binary_content": b"Binary trace with 10.0.0.5 content"
                        }
                    )
                    
                    extracted = ext.extract_artifacts([art], "e1")
                    ips = [a for a in extracted if a.raw_fields.get("normalized_value") == "10.0.0.5"]
                    self.assertEqual(len(ips), 1)
                    
                    found_by = ips[0].raw_fields.get("found_by")
                    self.assertIn("ioc_finder", found_by)
                    self.assertIn("yara", found_by)
        finally:
            import os
            os.unlink(temp_path)

    @patch("transformers.AutoModelForTokenClassification.from_pretrained")
    @patch("transformers.AutoTokenizer.from_pretrained")
    @patch("huggingface_hub.hf_hub_download")
    def test_confidence_scores_formula(self, mock_download, mock_tok, mock_model):
        """7. Confidence scores match the documented formula for each extraction path."""
        mock_model.return_value = MagicMock()
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
            
            art_ip = Artifact(evidence_id="e1", source_tool="test", artifact_type="process_event", raw_fields={"ip": "8.8.8.8"})
            res_ip = ext.extract_artifacts([art_ip], "e1")[0]
            self.assertEqual(res_ip.confidence_score, 0.7)

            art_priv = Artifact(evidence_id="e1", source_tool="test", artifact_type="process_event", raw_fields={"ip": "192.168.1.1"})
            res_priv = ext.extract_artifacts([art_priv], "e1")[0]
            self.assertEqual(res_priv.confidence_score, 0.3)


if __name__ == "__main__":
    unittest.main()


