import os
import sys
import unittest
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from preprocessing.schemas import Artifact
from preprocessing.artifact_extractor.extractor import ArtifactExtractor

_NEEDS_MODEL = os.environ.get("ARGUS_RUN_MODEL_INTEGRATION_TESTS")
_SKIP_REASON = "requires cached GLiNER weights — set ARGUS_RUN_MODEL_INTEGRATION_TESTS to run"

@unittest.skipUnless(_NEEDS_MODEL, _SKIP_REASON)
class TestAdversarialFpReduction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.extractor = ArtifactExtractor()

    def _extract(self, text: str, include_suppressed: bool = False):
        artifact = Artifact(
            evidence_id="ev-test",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": text}
        )
        return self.extractor.extract([artifact], "ev-test", include_suppressed=include_suppressed)

    def test_scenario_1_researcher_downgrade(self):
        # 1. "The Microsoft threat researcher Thomas published an analysis."
        # Expected: Thomas predicted_type = threat-actor, normalized_type != threat-actor, validation_status = downgraded
        ents = self._extract("The Microsoft threat researcher Thomas published an analysis.", include_suppressed=True)
        thomas_ents = [e for e in ents if e.value == "Thomas"]
        self.assertEqual(len(thomas_ents), 1)
        e = thomas_ents[0]
        self.assertEqual(e.predicted_type, "threat-actor")
        self.assertEqual(e.normalized_type, "unconfirmed_person")
        self.assertEqual(e.validation_status, "downgraded")
        self.assertEqual(e.suppression_reason, "negative_persona_indicator")

    def test_scenario_2_administrator_and_executable(self):
        # 2. "The administrator Thomas verified that update-X.exe is legitimate."
        # Expected: Thomas is not threat_actor, update-X.exe = executable.
        ents = self._extract("The administrator Thomas verified that update-X.exe is legitimate.", include_suppressed=True)
        thomas_ents = [e for e in ents if e.value == "Thomas"]
        self.assertEqual(len(thomas_ents), 1)
        self.assertEqual(thomas_ents[0].normalized_type, "unconfirmed_person")
        self.assertEqual(thomas_ents[0].validation_status, "downgraded")

        update_ents = [e for e in ents if "update-X.exe" in e.value]
        self.assertEqual(len(update_ents), 1)
        self.assertEqual(update_ents[0].normalized_type, "executable")

    def test_scenario_3_threat_actor_retained(self):
        # 3. "Threat actor Thomas deployed the malware."
        # Expected: Thomas = threat_actor candidate.
        ents = self._extract("Threat actor Thomas deployed the malware.", include_suppressed=True)
        thomas_ents = [e for e in ents if e.value == "Thomas"]
        self.assertEqual(len(thomas_ents), 1)
        self.assertEqual(thomas_ents[0].normalized_type, "threat_actor")
        self.assertEqual(thomas_ents[0].validation_status, "candidate")

    def test_scenario_4_generic_term_suppressed(self):
        # 4. "The threat actor launched the campaign."
        # Expected: "threat actor" is suppressed as a generic category term.
        ents_active = self._extract("The threat actor launched the campaign.", include_suppressed=False)
        generic_active = [e for e in ents_active if e.value.lower() == "threat actor"]
        self.assertEqual(len(generic_active), 0)

        ents_all = self._extract("The threat actor launched the campaign.", include_suppressed=True)
        generic_all = [e for e in ents_all if e.value.lower() == "threat actor"]
        self.assertEqual(len(generic_all), 1)
        self.assertEqual(generic_all[0].validation_status, "suppressed")
        self.assertEqual(generic_all[0].suppression_reason, "generic_category_term")

    def test_scenario_5_defensive_software(self):
        # 5. "Windows Defender detected the payload."
        # Expected: Windows Defender = software. Do not classify as malware.
        ents = self._extract("Windows Defender detected the payload.", include_suppressed=True)
        defender_ents = [e for e in ents if e.value == "Windows Defender"]
        self.assertEqual(len(defender_ents), 1)
        self.assertEqual(defender_ents[0].normalized_type, "software")
        self.assertNotEqual(defender_ents[0].normalized_type, "malware_candidate")

    def test_scenario_6_system_process(self):
        # 6. "LSASS was accessed during credential dumping."
        # Expected: LSASS = system_process. Do not classify as malware.
        ents = self._extract("LSASS was accessed during credential dumping.", include_suppressed=True)
        lsass_ents = [e for e in ents if e.value == "LSASS"]
        self.assertEqual(len(lsass_ents), 1)
        self.assertEqual(lsass_ents[0].normalized_type, "system_process")
        self.assertNotEqual(lsass_ents[0].normalized_type, "malware_candidate")

    def test_scenario_7_complete_command_line(self):
        # 7. "powershell.exe -NoProfile -EncodedCommand ABC"
        # Expected: complete command_line span.
        ents = self._extract("powershell.exe -NoProfile -EncodedCommand ABC", include_suppressed=True)
        cmd_ents = [e for e in ents if "powershell.exe" in e.value]
        self.assertEqual(len(cmd_ents), 1)
        self.assertEqual(cmd_ents[0].value, "powershell.exe -NoProfile -EncodedCommand ABC")
        self.assertEqual(cmd_ents[0].normalized_type, "command_line")

    def test_scenario_8_executable_not_command_line(self):
        # 8. "powershell.exe is mentioned in the report."
        # Expected: executable, not command_line.
        ents = self._extract("powershell.exe is mentioned in the report.", include_suppressed=True)
        cmd_ents = [e for e in ents if e.value == "powershell.exe"]
        self.assertEqual(len(cmd_ents), 1)
        self.assertIn(cmd_ents[0].normalized_type, ["executable", "system_process"])
        self.assertNotEqual(cmd_ents[0].normalized_type, "command_line")

if __name__ == "__main__":
    unittest.main()
