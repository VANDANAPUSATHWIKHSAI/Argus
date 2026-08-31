"""
Forensic Analysis Layer — Memory Analysis Engine Package
========================================================
Implements Layer-3 deterministic memory forensic analysis in ARGUS.
Orchestrates 7 sub-analyzers:
- ProcessAnalyzer
- DLLAnalyzer
- MemoryNetworkAnalyzer
- InjectionAnalyzer
- RootkitAnalyzer
- CredentialAnalyzer
- TimelineAnalyzer
"""

from forensic_analysis.memory_analysis.memory_engine import MemoryAnalysisEngine

__all__ = ["MemoryAnalysisEngine"]
