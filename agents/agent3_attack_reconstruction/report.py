from typing import Any
from agents.agent3_attack_reconstruction.schemas import Agent3Output

class Agent3ReportGenerator:
    """Generates the investigator-facing report from a validated Agent3Output."""

    @staticmethod
    def format_citations(evidence_ids: list[str], invalid_citations: list[str] = None) -> str:
        """Formats evidence IDs into a comma-separated string, filtering out invalid ones."""
        if invalid_citations:
            evidence_ids = [eid for eid in evidence_ids if eid not in invalid_citations]
        if not evidence_ids:
            return "No supporting evidence"
        return ", ".join(evidence_ids)

    @staticmethod
    def generate(output: Agent3Output) -> str:
        """Generates the human-readable forensic report."""
        if output.execution_status == "FAILED":
            reason = output.error_message or "Unknown failure"
            return (
                "OUTPUT\n------\n\n"
                "ATTACK RECONSTRUCTION REPORT\n----------------------------\n"
                "Attack reconstruction could not be completed from the available forensic evidence.\n\n"
                f"Reason:\n{reason}\n\n"
                "No unsupported attack events were generated."
            )

        report_lines = ["OUTPUT", "------", ""]

        # 1. INFECTION PATH
        report_lines.extend(["INFECTION PATH", "--------------"])
        
        path_events = []
        if output.infection_path.entry_point:
            path_events.append(output.infection_path.entry_point)
            
        for stage in output.attack_chain:
            for event in stage.events:
                if not path_events or path_events[-1] != event:
                    path_events.append(event)
            
        if path_events:
            report_lines.append("\n      | \n      v \n".join(path_events))
        else:
            report_lines.append("No infection path could be reconstructed.")
            
        report_lines.append("")

        # 2. CHRONOLOGICAL ATTACK PATH
        if output.attack_path:
            report_lines.extend(["ATTACK PATH", "-----------"])
            for step in sorted(output.attack_path, key=lambda x: x.step_number):
                cites = Agent3ReportGenerator.format_citations(step.evidence_ids, step.invalid_citations)
                report_lines.append(f"Step {step.step_number} [{step.stage}]: {step.description} (Evidence: {cites})")
            report_lines.append("")

        # 3. ATTACK TIMELINE
        report_lines.extend(["ATTACK TIMELINE", "---------------"])
        if not output.attack_timeline and not output.missing_expected_events:
            report_lines.append("No timeline events reconstructed.")
        else:
            for evt in sorted(output.attack_timeline, key=lambda x: x.timestamp):
                report_lines.append("")
                report_lines.append(f"{evt.timestamp}")
                report_lines.append(f"{evt.event}")
                report_lines.append(f"Stage: {evt.stage}")
                report_lines.append(f"Evidence: {Agent3ReportGenerator.format_citations(evt.evidence_ids, evt.invalid_citations)}")

            for missing in output.missing_expected_events:
                report_lines.append("")
                report_lines.append("Missing expected event:")
                report_lines.append(missing.event)
                report_lines.append(f"Reason: {missing.reason}")

        report_lines.append("")

        # 4. ATTACK RECONSTRUCTION REPORT
        report_lines.extend(["ATTACK RECONSTRUCTION REPORT", "----------------------------"])
        
        report_lines.append(f"CONFIRMED RECONSTRUCTION:")
        if output.reconstruction_summary:
            report_lines.append(output.reconstruction_summary)
        else:
            report_lines.append("No summary provided.")
            
        if output.lateral_movement:
            report_lines.append("\nLATERAL MOVEMENT:")
            for lm in output.lateral_movement:
                report_lines.append(f"- {lm.source_host} -> {lm.destination_host} via {lm.method} (Evidence: {Agent3ReportGenerator.format_citations(lm.evidence_ids, lm.invalid_citations)})")
                
        report_lines.append(f"\nOVERALL CONFIDENCE: {output.overall_confidence:.2f}")

        return "\n".join(report_lines)
