import unittest
from preprocessing.schemas import Artifact
from preprocessing.artifact_extractor.resolver import ProcessRelationshipResolver

class TestProcessRelationshipResolver(unittest.TestCase):
    def test_resolve_spawns_relationship_by_pid(self):
        # Admin cmd.exe spawns powershell.exe
        parent = Artifact(
            evidence_id="e1",
            source_tool="hayabusa",
            artifact_type="process_event",
            raw_fields={
                "pid": "4420",
                "ppid": "1000",
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c start",
                "timestamp": "2026-08-25T20:00:00Z"
            }
        )
        child = Artifact(
            evidence_id="e1",
            source_tool="hayabusa",
            artifact_type="process_event",
            raw_fields={
                "pid": "5890",
                "ppid": "4420",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc ...",
                "timestamp": "2026-08-25T20:00:02Z"
            }
        )

        resolver = ProcessRelationshipResolver()
        relationships = resolver.resolve_relationships([parent, child])

        self.assertEqual(len(relationships), 1)
        rel = relationships[0]
        self.assertEqual(rel["parent"]["pid"], 4420)
        self.assertEqual(rel["child"]["pid"], 5890)
        self.assertEqual(rel["relationship"], "SPAWNS")
        self.assertEqual(rel["provenance"]["source_tool"], "hayabusa")

    def test_resolve_spawns_relationship_fallback_by_name(self):
        # Resolve by name when PPID is missing but parent_process_name matches
        parent = Artifact(
            evidence_id="e2",
            source_tool="volatility3",
            artifact_type="process",
            raw_fields={
                "pid": "100",
                "process_name": "services.exe",
                "timestamp": "2026-08-25T19:00:00Z"
            }
        )
        child = Artifact(
            evidence_id="e2",
            source_tool="volatility3",
            artifact_type="process",
            raw_fields={
                "pid": "200",
                "process_name": "svchost.exe",
                "parent_process_name": "services.exe",
                "timestamp": "2026-08-25T19:00:01Z"
            }
        )

        resolver = ProcessRelationshipResolver()
        relationships = resolver.resolve_relationships([parent, child])

        self.assertEqual(len(relationships), 1)
        rel = relationships[0]
        self.assertEqual(rel["parent"]["process_name"], "services.exe")
        self.assertEqual(rel["child"]["process_name"], "svchost.exe")
        self.assertEqual(rel["relationship"], "SPAWNS")

if __name__ == "__main__":
    unittest.main()
