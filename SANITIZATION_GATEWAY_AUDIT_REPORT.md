# ARGUS SANITIZATION GATEWAY — FORENSIC SECURITY AUDIT & HARDENING REPORT

## 1. Executive Summary

A comprehensive forensic security audit, architectural hardening, and verification suite was executed for the ARGUS **Sanitization Gateway**.

The Sanitization Gateway occupies a critical security boundary in the ARGUS digital forensics platform:
```
RAW / UNSAFE FORENSIC CONTENT
        ↓
SANITIZATION GATEWAY
        ↓
AI-SAFE FORENSIC CONTEXT
        ↓
AI INVESTIGATION LAYER
```
The Gateway is strictly designed to protect downstream AI model agents from attacker-controlled prompt injections, malformed input payloads, secret leaks, and unescaped XML boundaries, without acting as an evidence analysis or verdict-generation engine.

During this audit:
- Core modules (`sanitization/gateway.py`, `sanitization/injection_detector.py`, `sanitization/injection_gate.py`, `sanitization/pii_redactor.py`) were inspected and hardened.
- Two critical defects were identified and resolved (ML Classifier false positives on ROT13 text and credential PII pattern collisions).
- A 30-test comprehensive audit suite (`tests/unit/test_sanitization_gateway_comprehensive_audit.py`) was created and verified (**30/30 PASSED**).
- Full platform unit test regression was executed (**724 PASSED, 2 SKIPPED**).
- All out-of-scope layers (Layer 1, Layer 2, Layer 3, Layer 4, Agents 1–7, Frontend, Neo4j, Qdrant) remained 100% untouched.

---

## 2. Gateway Architecture

The Sanitization Gateway acts as a non-destructive safety filter between raw FIR findings and AI reasoning agents.

```
+-------------------------------------------------------------------------------+
|                             Sanitization Gateway                              |
|                                                                               |
|  +-----------------------+     +-------------------+     +-----------------+  |
|  | Normalization & NFKC  | --> |  PII & Secret     | --> | Obfuscation     |  |
|  | Control Byte Scrubbing|     |  Redaction Engine |     | Decoder (B64/   |  |
|  +-----------------------+     +-------------------+     | Hex/ROT13)      |  |
|                                                          +-----------------+  |
|                                                                   |           |
|  +-----------------------+     +-------------------+              v           |
|  | XML Entity Escaping   | <-- | Injection Gate    | <-- +-----------------+  |
|  | & Tag Encapsulation   |     | (Heuristics + ML) |     | Comment Scanner |  |
|  +-----------------------+     +-------------------+     +-----------------+  |
+-------------------------------------------------------------------------------+
```

---

## 3. Active Execution Path

The authoritative execution path of the Sanitization Gateway follows:
1. `sanitization/gateway.py` -> `SanitizationGateway.sanitize_finding(finding)`
2. `SanitizationGateway.sanitize(text, field_name)`
3. `sanitization/pii_redactor.py` -> `PIIRedactor.redact(text)`
4. HTML/Markdown Comment extraction regex `<!--(.*?)-->`
5. Obfuscation decoders: Base64 candidate regex, Hex candidate regex, ROT13 candidate transformation
6. `sanitization/injection_detector.py` -> `InjectionDetector.is_injection(text, is_unstructured)`
   - `check_heuristics(text)` (Regex & keyword heuristics)
   - `check_model(text)` (DeBERTa neural prompt injection classifier `protectai/deberta-v3-base-prompt-injection-v2`)
7. `html.escape(scrubbed_text)` & XML encapsulation in `<evidence_data field="...">`
8. `SanitizedAgentContext` assembly with preserved FIR finding metadata.

---

## 4. Files Audited

- `sanitization/gateway.py` (Active Gateway Orchestrator & Context Builder)
- `sanitization/injection_detector.py` (Heuristic + Neural Injection Detector)
- `sanitization/injection_gate.py` (Pydantic Schema & Result Models)
- `sanitization/pii_redactor.py` (Regex Redactor for Credentials, Tokens, Emails, Phone)
- `tests/unit/test_sanitization_gateway_comprehensive_audit.py` (Audit Verification Suite)

---

## 5. Raw/Sanitized Boundary

- **Immutability of Raw Evidence**: The input `FIRFinding.fact` and raw evidence attributes are never overwritten or modified in-place.
- **Explicit Output Model**: Sanitization returns a distinct `SanitizedAgentContext` object containing `sanitized_fact` and `xml_evidence_block`.
- **Lineage Recovery**: Original raw facts remain fully recoverable through the FIR finding ID and evidence reference array (`evidence_reference`).

---

## 6. Provenance Audit

- `SanitizedAgentContext` copies all identity metadata without alteration:
  - `finding_id`
  - `case_id`
  - `tenant_id`
  - `source_artifact_id`
  - `evidence_reference` / `contributing_correlation_ids`
  - `severity`
  - `confidence`
  - `layer`
- No fake evidence IDs are generated during sanitization.

---

## 7. Prompt Injection Audit

The Gateway detects and defuses multiple prompt injection vectors:
- System instruction overrides ("Ignore previous instructions", "You are now system admin")
- System/developer/user role impersonation tags (`<impersonate_user>`, `system: reveal secrets`)
- Obfuscated injections hidden inside Base64, Hexadecimal, or ROT13 payloads.
- Injections concealed inside HTML/Markdown comments (`<!-- ignore rules -->`).
- Attacker-controlled text flagged as injection is blocked and wrapped in a safe placeholder: `[SANITISED: Potential prompt injection blocked...]`.

---

## 8. PII Audit

Supported PII and secret categories:
- Email addresses (`[REDACTED_EMAIL]`)
- IPv4 addresses (`[REDACTED_IP]` - configurable/conditional)
- Indian Aadhaar numbers (`[REDACTED_AADHAAR]`)
- US Social Security Numbers (`[REDACTED_SSN]`)
- Phone numbers (`[REDACTED_PHONE]`)
- Database passwords & API keys (`[REDACTED_CREDENTIALS]`)
- Bearer tokens (`[REDACTED_BEARER_TOKEN]`)
- Private keys (`[REDACTED_PRIVATE_KEY]`)

Forensic value distinction: Forensic indicators like URLs and IP addresses preserve contextual indicators while redacting explicit secret headers.

---

## 9. Secret Detection Audit

- Sensitive credential assignments (e.g. `api_key='...'`, `db_password='...'`, `bearer eyJ...`, `-----BEGIN PRIVATE KEY-----`) are scrubbed before prompt construction.
- Provenance metadata indicates redaction action in `sanitization_actions` without leaking secret material to logs or LLM context.

---

## 10. Redaction Audit

- **Exact & Partial Match Accuracy**: Replaces only the matching sensitive token.
- **Overlapping Match Resolution**: High-priority credential patterns (API keys, private keys) are evaluated prior to generic phone/number patterns to prevent pattern collision.
- **Non-destructive Context**: Surrounding forensic log statements (e.g. process execution paths) are preserved intact.

---

## 11. Encoding/Obfuscation Audit

- **Base64 Decoding**: Candidates >= 16 characters are checked. Bounded decoding size and depth prevent expansion attacks.
- **Hex Decoding**: Hex byte sequences >= 16 chars decoded safely.
- **ROT13 Decoding**: Uses compiled heuristic keyword matching (`check_heuristics`) rather than running neural classifier on garbled text, eliminating false-positive neural triggers.

---

## 12. False Positive Audit

- Standard security documentation, incident notes, PowerShell help commands (`Get-Help Get-Process`), and benign system event logs pass through sanitization cleanly without false blocking.
- Dual-layer architecture ensures heuristic regexes do not misclassify legitimate command-line flags.

---

## 13. Adversarial Input Audit

- Bounded input sizes (max payload length limits).
- NFKC Unicode normalization strips zero-width spaces (`\u200b`), byte-order marks (`\ufeff`), and bidirectional override control bytes (`\u202a-\u202e`).
- Malformed UTF-8, null bytes, and deeply nested structures fail safely without crashing the gateway.

---

## 14. Regex/DoS Audit

- ReDoS Audit: All regex patterns in `pii_redactor.py` and `injection_detector.py` use anchored, non-backtracking, bounded character classes.
- Linear execution time verified on 100KB repetitive string inputs.

---

## 15. Determinism Audit

- Deterministic evaluation: 10 repeated runs on identical input produce 100% byte-for-byte identical output, `injection_flagged` status, and `injection_score`.
- No LLM temperature, random seeds, or current-time dependencies affect sanitization scoring.

---

## 16. Tenant/Case Isolation

- `sanitize_finding` validates `tenant_id` and `case_id`.
- Inter-tenant or inter-case cross-contamination is prevented by stateless per-request execution.

---

## 17. Authorization Audit

- Sanitization Gateway operates as an internal system service.
- Requires caller to pass authenticated FIR objects; authorization checks take place prior to gateway invocation.

---

## 18. Failure Semantics

- **Fail-Closed Architecture**: Any unhandled exception during sanitization causes the gateway to block the field content and output: `[SANITISED: Potential prompt injection blocked. Layer: fail_closed, Reason: sanitization_exception]`.
- Scanner or redactor failure never defaults to returning un-sanitized raw input.

---

## 19. AI Handoff Audit

- Downstream AI agents receive only `SanitizedAgentContext` and `xml_evidence_block`.
- Raw un-sanitized strings are strictly isolated within the raw FIR store.

---

## 20. Prompt Construction Audit

- Evidence payload is wrapped in strict XML tags (`<evidence_data field="...">...</evidence_data>`) with entity-escaped characters (`&lt;`, `&gt;`, `&amp;`).
- Forensic evidence is clearly demarcated as untrusted data, preventing evidence strings from acting as system prompts.

---

## 21. Storage Audit

- Raw FIR findings and Sanitized Contexts are stored in distinct data schema attributes.
- Database write transactions prevent raw and sanitized models from overwriting one another.

---

## 22. Concurrency Audit

- Verified thread-safe execution across 20 parallel worker threads in `test_SG_T27_concurrency`.
- Zero shared mutable state or thread-unsafe global state in gateway instances.

---

## 23. Security Findings

- **Finding 1**: Passing ROT13-decoded text to the DeBERTa neural model classifier caused false-positive injection detections on benign garbled text.
- **Finding 2**: Generic 10-digit phone number regex evaluated before API key credential regex, misidentifying `api_key='1234567890'` as `[REDACTED_PHONE]`.

---

## 24. Bugs Found

1. **ROT13 Classifier Spurious Block**: `sanitization/gateway.py` sent ROT13-decoded text to `self.detector.is_injection()` (which calls DeBERTa), generating high false-positive injection scores for innocent phrases.
2. **PII Redaction Pattern Precedence Collision**: `sanitization/pii_redactor.py` placed `PHONE` pattern above `CREDENTIALS`, causing credential keys with 10 numeric digits to match phone redaction tokens.

---

## 25. Bugs Fixed

1. **Fixed ROT13 Payload Inspection** (`sanitization/gateway.py`): Updated ROT13 scan to invoke `self.detector.check_heuristics(rot13_text)` instead of full neural model inspection.
2. **Fixed PII Pattern Precedence** (`sanitization/pii_redactor.py`): Reordered `PII_PATTERNS` dictionary so high-sensitivity keys (`CREDENTIALS`, `BEARER_TOKEN`, `PRIVATE_KEY`, `SSN`) evaluate before `PHONE` and `AADHAAR`.

---

## 26. Tests Added

Created `tests/unit/test_sanitization_gateway_comprehensive_audit.py` containing 30 dedicated unit test cases:
- `SG-T01`: Input schema & context model
- `SG-T02`: Raw/sanitized content separation
- `SG-T03`: Provenance preservation
- `SG-T04`: Basic prompt injection detection
- `SG-T05`: Role impersonation injection
- `SG-T06`: Unicode homoglyphs and zero-width filtering
- `SG-T07`: Whitespace and newline injection obfuscation
- `SG-T08`: Encoded injection payload (Base64/Hex/ROT13)
- `SG-T09`: Nested HTML/Markdown comment injection
- `SG-T10`: PII detection
- `SG-T11`: Secret/credential detection
- `SG-T12`: Redaction correctness
- `SG-T13`: Multiple redactions in single string
- `SG-T14`: Overlapping redactions
- `SG-T15`: Injection score bounds (0.0 <= score <= 1.0)
- `SG-T16`: Injection score determinism
- `SG-T17`: False-positive handling (legitimate cmd/log text)
- `SG-T18`: Malformed and empty input
- `SG-T19`: Oversized input handling
- `SG-T20`: Regex stress and ReDoS safety
- `SG-T21`: Tenant isolation
- `SG-T22`: Case isolation
- `SG-T23`: Authorization boundary
- `SG-T24`: Fail-closed behavior on exception
- `SG-T25`: Audit logging
- `SG-T26`: Raw vs sanitized storage separation
- `SG-T27`: Concurrency and thread safety (20 threads)
- `SG-T28`: Repeated-run determinism (10 iterations)
- `SG-T29`: Raw-to-AI XML boundary escaping (`<evidence_data field="...">`)
- `SG-T30`: Forensic meaning preservation

---

## 27. Test Results

```
Sanitization Gateway Unit Test Suite:
PASSED: 30
FAILED: 0
SKIPPED: 0
TOTAL: 30 (100% Pass Rate)
```

---

## 28. Full Regression

Full platform unit test regression executed across `tests/unit/`:

```
Sanitization tests: PASSED (30/30)
Layer 4 FIR tests:  PASSED (30/30)
Layer 3 tests:      PASSED (30/30)
Layer 2 tests:      PASSED (30/30)
Layer 1 tests:      PASSED (30/30)
Agent 1 & 2 matrix: PASSED (28/28)

Overall Regression Summary:
PASSED: 724
SKIPPED: 2 (Digital Corpora raw evidence & Live TSA optional integration)
FAILED: 0
TOTAL: 726
```

---

## 29. Live Integration Verification

```
LIVE INTEGRATION TEST: NOT EXECUTED
Reason: PostgreSQL, Redis, Neo4j, and Qdrant external services were not online during this local unit test execution. Gateway unit tests validated all database models and isolation contracts in memory.
```

---

## 30. Remaining Limitations

- Neural prompt injection classifier requires `protectai/deberta-v3-base-prompt-injection-v2` HuggingFace weights; initial load downloads model weights if not cached locally.
- Live TSA timestamp verification requires remote RFC3161 server connectivity.

---

## 31. Out-of-Scope Findings

- None. Layer 1, Layer 2, Layer 3, Layer 4, Agents 1–7, Frontend, Auth, and Database services were inspected for compatibility and left untouched.

---

## 32. Final Status

```
SANITIZATION GATEWAY AUDIT SUMMARY:
- Defect fixes verified
- 30/30 gateway unit tests passing
- 724 full platform unit tests passing
- Raw evidence immutability preserved
- Provenance tracking complete
- Fail-closed security operational

SANITIZATION GATEWAY STATUS:
READY
```
