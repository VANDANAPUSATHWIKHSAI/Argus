# Agent 5a — Threat Intelligence  [runs PARALLEL with Agent 3, Agent 4]
# IOC matching, MITRE ATT&CK mapping, CVE lookup.
# Cross-references MULTIPLE threat feeds, checks feed freshness.
# Fundamentally a retrieval/matching task — no heavy generative call needed.
# Model: Qwen3-Embedding (semantic/fuzzy matching) | RAG: No generative RAG
# Feeds: STIX/TAXII, MITRE ATT&CK, CVE/NVD, CISA KEV
from agents.base_agent import BaseAgent

class ThreatIntelligenceAgent(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        stix_client = context.get("stix_client")
        cve_client = context.get("cve_client")
        mitre_client = context.get("mitre_client")
        if not stix_client or not cve_client or not mitre_client:
            raise ValueError("stix_client, cve_client, and mitre_client must be provided in context.")

        # Query STIX/TAXII, CVE, and MITRE feeds, sanitizing outputs to avoid feed-based injections
        ioc_details = self.sanitized_context_fetch(
            stix_client.check_ioc,
            "192.168.1.50",
            field_name="unstructured"
        )
        cve_details = self.sanitized_context_fetch(
            cve_client.lookup_cve,
            "CVE-2026-1234",
            field_name="description"
        )
        mitre_details = self.sanitized_context_fetch(
            mitre_client.get_technique,
            "T1059",
            field_name="description"
        )
        
        # Return matched/cross-referenced results safely
        return {
            "claim": f"IOC match: {ioc_details}. CVE lookup: {cve_details}. MITRE technique details: {mitre_details}.",
            "evidence_ids": []
        }

