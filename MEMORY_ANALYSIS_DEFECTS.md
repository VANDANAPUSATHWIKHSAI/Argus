# Memory Analysis Engine — Defects & Remediation Log

| Defect ID | Component | Description | Resolution / Status |
|---|---|---|---|
| **DEF-MEM-001** | `test_analysis_engines.py` | `test_process_fcr_batch_integration` failed when `'memory'` was registered in `ENGINE_REGISTRY` because it expected an unregistered engine warning. | Updated test artifact from `memory.pslist` to `email.header` to properly test unregistered engine (`'email'`) warning logging. |
| **DEF-MEM-002** | Credential Analyzer | Risk of credential leaks (passwords, hashes, tokens) in findings or metadata. | Implemented mandatory secret redaction filter in `CredentialAnalyzer`. Only safe metadata (`PID`, `process_name`, `structure_type`, `redacted=True`) is stored. Verified via `test_credential_analyzer_redaction_security`. |
| **DEF-MEM-003** | AST Security | Risk of unsafe dynamic code execution or command execution via memory artifact strings. | Verified 0 dynamic code execution (`eval`, `exec`, `shell=True`, `os.system`) via AST inspection test `test_ast_security_inspection`. |
