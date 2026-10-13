# Project ARGUS: Agent 6 (Impact Assessment) Implementation Plan

## 1. Executive Summary & Core Mission

Agent 6 answers the central forensic questions of the investigation:
> **"What assets and identities were affected, how serious is the breach mathematically and operationally, and what prioritized recovery actions must the incident response team take?"**

### Master Architectural Rule
$$\text{Evidence First} \longrightarrow \text{Deterministic Analysis} \longrightarrow \text{AI Reasoning} \longrightarrow \text{Verification Gate} \longrightarrow \text{Audit Persistence}$$

- **Numerical Inviolability**: Technical severity (CVSS v3.1) and business impact (ISS) are **strictly calculated by deterministic Python engines**.
- **LLM Boundary**: **Qwen3-8B** explains and narrates the findings; it is **strictly forbidden from overriding, calculating, or altering any numerical score**.
- **Anti-Hallucination Guard**: Missing or partial forensic evidence yields `INSUFFICIENT_DATA` / `UNDETERMINED` rather than guessing an arbitrary 9.8 Critical score.

---

## 2. Pipeline Position & Data Flow

Agent 6 consumes structured findings from upstream agents and delivers the finalized impact assessment to **Agent 7 (Supervisor)**.

```
+-----------------------------------------------------------------------------+
|                               UPSTREAM AGENTS                               |
|   Agent 1 (Evidence) -> Agent 2 (Correlation) -> Agents 3-5 (Reconstruction)|
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                    AGENT 6: IMPACT ASSESSMENT PIPELINE                     |
|                                                                             |
|  1. Sanitization Gateway (protectai/deberta-v3 prompt-injection check)     |
|                               |                                             |
|  2. Asset Discovery Engine   |--> Extracted Hosts, DCs, Accounts, Risk     |
|                               |                                             |
|  3. Evidence-to-CVSS Mapper  |--> CVSS v3.1 Metrics or INSUFFICIENT_DATA   |
|                               |                                             |
|  4. CVSS v3.1 Math Engine    |--> Base Score (0.0-10.0), Subscores, Vector  |
|                               |                                             |
|  5. ISS Business Engine      |--> 6-Dimension Weighted Score (0.0-10.0)     |
|                               |                                             |
|  6. Recovery Playbook Engine |--> 4-Phase Lifecycle Checklist (P1 to P4)    |
|                               |                                             |
|  7. Qwen3-8B Narration       |--> Structured 5-Section Executive Narrative  |
|                               |                                             |
|  8. Validation Gate          |--> Citation Universe & Math Verification     |
+-----------------------------------------------------------------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
         PostgreSQL Persistence                   Agent 7 (Supervisor)
```

---

## 3. Component Architecture & File Structure

Agent 6 is organized as a modular package under `Argus/agents/agent6_impact_assessment/`:

| File | Component | Primary Responsibility |
| :--- | :--- | :--- |
| `schemas.py` | **Pydantic v2 Contracts** | Enforces strict schemas for CVSS metrics, ISS factors, asset inventories, recovery actions, and `Agent6Output`. |
| `cvss_calculator.py` | **CVSS v3.1 Engine** | Official FIRST.org specification with Appendix A floating-point `roundup()`, Exploitability/Impact subscores, and boundary estimators. |
| `cvss_mapper.py` | **Evidence Mapper** | Maps forensic findings to CVSS metrics. Enforces `INSUFFICIENT_DATA` guards when evidence is missing. |
| `iss_calculator.py` | **ISS Business Calculator** | Computes the 6-factor investigation severity score with weights strictly summing to 1.00. |
| `asset_extractor.py` | **Asset Discovery** | Scans findings for hostnames, Domain Controllers, IP addresses, and user accounts with risk scoring. |
| `recovery_engine.py` | **Playbook Engine** | Generates prioritized playbooks across 4 incident response phases (Containment, Eradication, Recovery, Hardening). |
| `prompts.py` | **Prompt Guardrails** | System and user prompts for Qwen3-8B requiring strict adherence to pre-computed scores and cited evidence. |
| `validator.py` | **Verification Gate** | Audits citation universe validity and verifies that narrative numbers match mathematical computations. |
| `agent.py` | **Orchestrator** | Subclasses `BaseAgent`, handles sanitization, coordinates engines, invokes Qwen3-8B, and persists results. |
| `run_agent6.py` | **CLI Test Runner** | Standalone command-line interface for running evidence files and inspecting reports. |

---

## 4. Key Engineering Modules & Equations

### A. Technical Severity: FIRST.org CVSS v3.1 Calculator
- **Base Metrics**: Attack Vector (`AV`), Attack Complexity (`AC`), Privileges Required (`PR`), User Interaction (`UI`), Scope (`S`), Confidentiality (`C`), Integrity (`I`), Availability (`A`).
- **ISS Subscores**:
  $$\text{ISS}_{\text{base}} = 1 - \big[(1 - C) \times (1 - I) \times (1 - A)\big]$$
  $$\text{Impact} = \begin{cases} 6.42 \times \text{ISS}_{\text{base}} & \text{if Scope Unchanged} \\ 7.52 \times (\text{ISS}_{\text{base}} - 0.029) - 3.25 \times (\text{ISS}_{\text{base}} - 0.02)^{15} & \text{if Scope Changed} \end{cases}$$
  $$\text{Exploitability} = 8.22 \times AV \times AC \times PR \times UI$$
- **Appendix A Floating-Point Roundup**:
  $$\text{Roundup}(x) = \lceil x \times 10 \rceil / 10$$
- **Anti-Hallucination Guard**: If any metric cannot be verified from evidence, the engine sets `assessment_status = INSUFFICIENT_DATA` and `base_score = None`. Unsubstantiated metrics are never guessed.

### B. Investigation Severity Score (ISS) Engine
Separates incident business risk from technical vulnerability scores using 6 weighted dimensions summing strictly to $1.00$:

$$\text{ISS} = \sum_{i=1}^{6} (w_i \times s_i)$$

| Dimension | Weight ($w_i$) | Forensic Basis |
| :--- | :---: | :--- |
| **Asset Criticality & Exposure** | **0.25** | Compromised tier (Domain Controller: 9.5, Core DB: 8.5, Standard Host: 5.0) |
| **Data Compromise & Confidentiality** | **0.20** | Confirmed data exfiltration, credential harvesting, or unauthorized reads |
| **System Integrity & Persistence Depth** | **0.20** | Rootkits/boot persistence (10.0), scheduled tasks/registry (7.5), scripts (5.0) |
| **Operational Availability & Downtime** | **0.15** | DoS, ransomware lockouts, critical service disruption |
| **Scope & Lateral Movement** | **0.10** | Enterprise-wide pivot (9.0), secondary host (6.0), single host (2.0) |
| **Technical Vulnerability Baseline** | **0.10** | Deterministic CVSS Base Score scaled to 10.0 (or 5.0 default if undetermined) |

---

## 5. Operational Recovery Lifecycle Checklist

The recovery engine automatically generates targeted, assigned, and verifiable tasks across 4 standardized phases:

```
[PHASE 1: CONTAINMENT] (Target: 1-2 Hours | Priority: P1_IMMEDIATE)
  ├── REC-001: Network quarantine of compromised endpoints (SOC L2)
  ├── REC-002: Perimeter firewall block for C2 IP/domain indicators (Network Admin)
  └── REC-003: Revocation of Kerberos tickets & password reset for compromised identities (IAM Admin)

[PHASE 2: ERADICATION] (Target: 6-12 Hours | Priority: P2_HIGH)
  ├── REC-004: Removal of persistence mechanisms (scheduled tasks, run keys, services) (SysAdmin)
  └── REC-005: Custom YARA rule scans across storage volumes for secondary droppers (Forensic Analyst)

[PHASE 3: RECOVERY] (Target: 24-48 Hours | Priority: P3_MEDIUM)
  ├── REC-006: Re-imaging impacted endpoints from verified clean golden images (SysAdmin)
  └── REC-007: Phased network re-attachment under 72-hour elevated EDR telemetry monitoring (SOC L2)

[PHASE 4: POST-INCIDENT HARDENING] (Priority: P4_LOW)
  ├── REC-008: Enforcement of PowerShell ConstrainedLanguage & Attack Surface Reduction (SysAdmin)
  └── REC-009: Deployment of new SIEM detection rules for observed attacker TTPs (Detection Eng)
```

---

## 6. Verification & Quality Gates

Before any Agent 6 assessment is finalized, it must pass through two independent safety gates:

1. **Pre-LLM Sanitization Gateway**:
   - Every finding description is analyzed with `protectai/deberta-v3-base-prompt-injection-v2`.
   - Adversarial prompt injection payloads embedded in logs or forensic artifacts are neutralized before reaching Qwen3-8B.
2. **Post-LLM Validation Gate (`validator.py`)**:
   - **Citation Universe Check**: Ensures every cited evidence ID exists in the input evidence.
   - **Math Verification**: Compares numbers in the LLM text with the deterministic CVSS and ISS engines. If a mismatch is detected, the narrative falls back to the deterministic generator.

---

## 7. How to Test and Run Agent 6

### Running the Test Suite
```powershell
# From Project_Argus/Argus directory:
..\venv\Scripts\python.exe -m pytest tests/unit/test_agent6_impact_assessment.py
..\venv\Scripts\python.exe test_agent6_verification.py
```

### Running Evidence CLI
```powershell
# Built-in realistic multi-stage forensic attack simulation:
..\venv\Scripts\python.exe run_agent6.py --export-json final_report.json

# Upstream Agent 2 / Agent 3 case file:
..\venv\Scripts\python.exe run_agent6.py --case-file "../files/agent2_output_2020JimmyWilson.json"

# Inspect help options:
..\venv\Scripts\python.exe run_agent6.py --help
```
