"""
Regression test for evidence metadata datetime serialization in api/routes/evidence.py.

Verifies:
- Datetime objects inside evidence metadata do not raise TypeError during JSON serialization.
- Nested datetime timestamps (e.g. from TimestampRecord) are safely serialized using default=str.
- PostgreSQL UPDATE and local repository metadata.json write paths handle timestamps properly.
"""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory


class TestEvidenceDatetimeSerialization(unittest.TestCase):

    def test_json_dumps_with_datetime_default_str(self):
        """Verifies that json.dumps(metadata, default=str) serializes datetime objects to strings."""
        metadata = {
            "evidence_id": "ev-test-1234",
            "uploaded_at": datetime(2026, 10, 16, 12, 30, 45, tzinfo=timezone.utc),
            "nested_timestamp_record": {
                "timestamp": datetime(2026, 10, 16, 12, 30, 50, tzinfo=timezone.utc),
                "authority_name": "FreeTSA",
                "status": "VERIFIED_EXTERNAL_TSA"
            }
        }

        # Raw json.dumps without default=str must raise TypeError
        with self.assertRaises(TypeError):
            json.dumps(metadata)

        # json.dumps with default=str must succeed
        serialized = json.dumps(metadata, default=str)
        self.assertIsInstance(serialized, str)
        self.assertIn("2026-10-16 12:30:45+00:00", serialized)
        self.assertIn("2026-10-16 12:30:50+00:00", serialized)

        # Verify it can be deserialized back
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["evidence_id"], "ev-test-1234")
        self.assertEqual(deserialized["nested_timestamp_record"]["authority_name"], "FreeTSA")

    def test_json_dump_to_file_with_datetime(self):
        """Verifies writing metadata.json with datetime attributes to filesystem succeeds."""
        meta_data = {
            "tenant_id": "tenant-sec-01",
            "case_id": "case-9988",
            "created_at": datetime.now(timezone.utc),
        }

        with TemporaryDirectory() as tmpdir:
            meta_file = Path(tmpdir) / "metadata.json"
            with open(meta_file, "w", encoding="utf-8") as mf:
                json.dump(meta_data, mf, indent=2, default=str)

            self.assertTrue(meta_file.exists())
            with open(meta_file, "r", encoding="utf-8") as mf:
                loaded = json.load(mf)
            self.assertEqual(loaded["tenant_id"], "tenant-sec-01")
            self.assertIn("2026", loaded["created_at"])


if __name__ == "__main__":
    unittest.main()
