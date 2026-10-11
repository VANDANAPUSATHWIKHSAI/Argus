"""
CVSS v3.1 Deterministic Calculator
==================================
Implements the exact FIRST.org Common Vulnerability Scoring System (CVSS) v3.1 specification.
Provides mathematical precision for Base Score calculation, Exploitability/Impact subscores,
vector formatting, and score range bounding for partial assessments.

References:
  FIRST CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from typing import Dict, Any, Tuple, Optional, List
from agents.agent6_impact_assessment.schemas import CVSSSeverity


class CVSS31Constants:
    # Attack Vector (AV)
    AV_WEIGHTS = {
        "NETWORK": 0.85,          "N": 0.85,
        "ADJACENT_NETWORK": 0.62, "A": 0.62,
        "LOCAL": 0.55,            "L": 0.55,
        "PHYSICAL": 0.20,         "P": 0.20,
    }

    # Attack Complexity (AC)
    AC_WEIGHTS = {
        "LOW": 0.77,  "L": 0.77,
        "HIGH": 0.44, "H": 0.44,
    }

    # Privileges Required (PR)
    # Dict of Scope -> PR value -> weight
    PR_WEIGHTS_UNCHANGED = {
        "NONE": 0.85, "N": 0.85,
        "LOW": 0.62,  "L": 0.62,
        "HIGH": 0.27, "H": 0.27,
    }
    PR_WEIGHTS_CHANGED = {
        "NONE": 0.85, "N": 0.85,
        "LOW": 0.68,  "L": 0.68,
        "HIGH": 0.50, "H": 0.50,
    }

    # User Interaction (UI)
    UI_WEIGHTS = {
        "NONE": 0.85,     "N": 0.85,
        "REQUIRED": 0.62, "R": 0.62,
    }

    # Scope (S)
    SCOPE_VALUES = {
        "UNCHANGED": "U", "U": "U",
        "CHANGED": "C",   "C": "C",
    }

    # Impact Metrics: Confidentiality (C), Integrity (I), Availability (A)
    CIA_WEIGHTS = {
        "NONE": 0.00, "N": 0.00,
        "LOW": 0.22,  "L": 0.22,
        "HIGH": 0.56, "H": 0.56,
    }

    # Metric Code Mapping
    CODE_TO_METRIC = {
        "AV": "attack_vector",
        "AC": "attack_complexity",
        "PR": "privileges_required",
        "UI": "user_interaction",
        "S":  "scope",
        "C":  "confidentiality",
        "I":  "integrity",
        "A":  "availability",
    }


def cvss_roundup(val: float) -> float:
    """
    Official FIRST.org CVSS v3.1 roundup function:
    Smallest number, specified to 1 decimal place, >= input.
    Accounts for IEEE 754 floating point representation quirks.
    """
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0


def derive_cvss_severity(score: Optional[float]) -> CVSSSeverity:
    """Derives qualitative severity from CVSS base score."""
    if score is None:
        return CVSSSeverity.UNDETERMINED
    if score == 0.0:
        return CVSSSeverity.NONE
    elif 0.1 <= score <= 3.9:
        return CVSSSeverity.LOW
    elif 4.0 <= score <= 6.9:
        return CVSSSeverity.MEDIUM
    elif 7.0 <= score <= 8.9:
        return CVSSSeverity.HIGH
    elif 9.0 <= score <= 10.0:
        return CVSSSeverity.CRITICAL
    return CVSSSeverity.UNDETERMINED


class CVSSCalculator:
    """
    Pure Python deterministic CVSS v3.1 Base Score calculator.
    Never hallucinates or guesses values.
    """

    @classmethod
    def calculate_base_score(cls, metrics: Dict[str, str]) -> Dict[str, Any]:
        """
        Calculates CVSS v3.1 base score from metric dictionary.
        Accepts full names or short codes (e.g. {'AV': 'N', 'AC': 'L', ...} or
        {'attack_vector': 'NETWORK', ...}).

        Returns dict containing:
          - base_score (float)
          - exploitability_subscore (float)
          - impact_subscore (float)
          - severity (CVSSSeverity)
          - vector_string (str)
        """
        normalized = cls._normalize_metrics(metrics)
        missing = [m for m in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] if m not in normalized]
        if missing:
            raise ValueError(f"Missing required CVSS v3.1 metrics: {missing}")

        av_val = normalized["AV"]
        ac_val = normalized["AC"]
        pr_val = normalized["PR"]
        ui_val = normalized["UI"]
        s_val  = normalized["S"]
        c_val  = normalized["C"]
        i_val  = normalized["I"]
        a_val  = normalized["A"]

        # Numeric weights
        av_weight = CVSS31Constants.AV_WEIGHTS[av_val]
        ac_weight = CVSS31Constants.AC_WEIGHTS[ac_val]
        ui_weight = CVSS31Constants.UI_WEIGHTS[ui_val]

        scope_changed = (s_val == "C")
        if scope_changed:
            pr_weight = CVSS31Constants.PR_WEIGHTS_CHANGED[pr_val]
        else:
            pr_weight = CVSS31Constants.PR_WEIGHTS_UNCHANGED[pr_val]

        c_weight = CVSS31Constants.CIA_WEIGHTS[c_val]
        i_weight = CVSS31Constants.CIA_WEIGHTS[i_val]
        a_weight = CVSS31Constants.CIA_WEIGHTS[a_val]

        # 1. Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c_weight) * (1.0 - i_weight) * (1.0 - a_weight))

        # 2. Impact
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Exploitability
        exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight

        # 4. Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if not scope_changed:
                base_score = cvss_roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cvss_roundup(min(1.08 * (impact + exploitability), 10.0))

        # Subscores rounded for standard reporting
        exploitability_rounded = round(exploitability, 1)
        impact_rounded = round(impact, 1)

        vector_string = f"CVSS:3.1/AV:{av_val}/AC:{ac_val}/PR:{pr_val}/UI:{ui_val}/S:{s_val}/C:{c_val}/I:{i_val}/A:{a_val}"
        severity = derive_cvss_severity(base_score)

        return {
            "base_score": base_score,
            "exploitability_subscore": exploitability_rounded,
            "impact_subscore": impact_rounded,
            "severity": severity,
            "vector_string": vector_string
        }

    @classmethod
    def estimate_score_bounds(
        cls,
        confirmed_metrics: Dict[str, str],
        missing_metric_codes: List[str]
    ) -> Tuple[float, float]:
        """
        Determines the mathematical minimum and maximum possible CVSS base scores
        for the remaining missing metrics.
        Never guesses: demonstrates the verified score boundary based solely on known facts.
        """
        if not missing_metric_codes:
            res = cls.calculate_base_score(confirmed_metrics)
            return (res["base_score"], res["base_score"])

        norm = cls._normalize_metrics(confirmed_metrics)

        # Define least severe vs most severe values
        min_defaults = {
            "AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U",
            "C": "N", "I": "N", "A": "N"
        }
        max_defaults = {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
            "C": "H", "I": "H", "A": "H"
        }

        min_scenario = dict(norm)
        max_scenario = dict(norm)

        for m in missing_metric_codes:
            code = cls._to_code(m)
            min_scenario[code] = min_defaults[code]
            max_scenario[code] = max_defaults[code]

        min_score = cls.calculate_base_score(min_scenario)["base_score"]
        max_score = cls.calculate_base_score(max_scenario)["base_score"]

        return (min_score, max_score)

    @classmethod
    def _to_code(cls, metric_key: str) -> str:
        k = metric_key.upper().strip()
        if k in {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}:
            return k
        mapping = {
            "ATTACK_VECTOR": "AV",
            "ATTACK VECTOR": "AV",
            "ATTACK_COMPLEXITY": "AC",
            "ATTACK COMPLEXITY": "AC",
            "PRIVILEGES_REQUIRED": "PR",
            "PRIVILEGES REQUIRED": "PR",
            "USER_INTERACTION": "UI",
            "USER INTERACTION": "UI",
            "SCOPE": "S",
            "CONFIDENTIALITY": "C",
            "INTEGRITY": "I",
            "AVAILABILITY": "A"
        }
        return mapping.get(k, k)

    @classmethod
    def _normalize_metrics(cls, metrics: Dict[str, str]) -> Dict[str, str]:
        """Normalizes input metric dict to short codes (e.g. 'AV': 'N')."""
        norm = {}
        for key, raw_val in metrics.items():
            code = cls._to_code(key)
            val = str(raw_val).upper().strip()

            if code == "AV":
                mapping = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P", "N": "N", "A": "A", "L": "L", "P": "P"}
                if val in mapping:
                    norm[code] = mapping[val]
            elif code == "AC":
                mapping = {"LOW": "L", "HIGH": "H", "L": "L", "H": "H"}
                if val in mapping:
                    norm[code] = mapping[val]
            elif code == "PR":
                mapping = {"NONE": "N", "LOW": "L", "HIGH": "H", "N": "N", "L": "L", "H": "H"}
                if val in mapping:
                    norm[code] = mapping[val]
            elif code == "UI":
                mapping = {"NONE": "N", "REQUIRED": "R", "N": "N", "R": "R"}
                if val in mapping:
                    norm[code] = mapping[val]
            elif code == "S":
                mapping = {"UNCHANGED": "U", "CHANGED": "C", "U": "U", "C": "C"}
                if val in mapping:
                    norm[code] = mapping[val]
            elif code in {"C", "I", "A"}:
                mapping = {"NONE": "N", "LOW": "L", "HIGH": "H", "N": "N", "L": "L", "H": "H"}
                if val in mapping:
                    norm[code] = mapping[val]

        return norm
