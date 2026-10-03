"""
Forensic Analysis Layer — Deterministic Rule Engines Package
=============================================================
Provides Sigma (log/telemetry) and YARA (binary/file) rule matching engines
as sub-analyzers within the existing forensic analysis layer.

Both engines produce standard forensic_analysis.schemas.Finding objects,
following the same contract used by all other deterministic sub-analyzers
(ProcessCreationAnalyzer, InjectionAnalyzer, etc.).

See SUPPORTED_SIGMA_SUBSET.md for the documented Sigma condition subset.
"""

from forensic_analysis.rules.sigma_engine import SigmaRuleEngine
from forensic_analysis.rules.yara_engine import YaraRuleEngine

__all__ = ["SigmaRuleEngine", "YaraRuleEngine"]
