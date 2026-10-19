/**
 * ARGUS Dedicated Deterministic Mock Data Layer for Design Template Previews
 * Corporate Data Exfiltration & Systems Compromise Scenario
 */

export const PREVIEW_MOCK_CASES = [
  {
    case_id: 'CASE-2026-001',
    name: 'FIN-EXFIL-2026: Corporate Treasury Breach',
    description: 'Suspected unauthorized exfiltration of encrypted financial database backups via compromised domain controller admin credentials.',
    status: 'IN_PROGRESS',
    risk_level: 'HIGH',
    assigned_to: 'Lead Analyst Sathwik',
    created_at: '2026-10-10 14:22:00',
    tenant_id: 'tenant-finance-corp',
    total_findings: 8,
    total_evidence: 6,
    critical_findings: 2,
    high_severity: 3,
    medium_severity: 2,
    low_severity: 1
  },
  {
    case_id: 'CASE-2026-002',
    name: 'SEC-RANSOM-094: Production Cluster Intrusion',
    description: 'Anomalous PowerShell execution and lateral movement detected across AWS EKS production nodes.',
    status: 'UNDER_REVIEW',
    risk_level: 'CRITICAL',
    assigned_to: 'Senior Specialist Marcus',
    created_at: '2026-10-09 09:15:30',
    tenant_id: 'tenant-cloud-ops',
    total_findings: 12,
    total_evidence: 8,
    critical_findings: 4,
    high_severity: 5,
    medium_severity: 2,
    low_severity: 1
  },
  {
    case_id: 'CASE-2026-003',
    name: 'HR-INSIDER-012: Confidential Records Leak',
    description: 'Internal data access violation involving unauthorized bulk export of employee PII records to USB storage.',
    status: 'CLOSED',
    risk_level: 'MEDIUM',
    assigned_to: 'Auditor Inspector Vance',
    created_at: '2026-10-08 17:40:12',
    tenant_id: 'tenant-hr-global',
    total_findings: 4,
    total_evidence: 3,
    critical_findings: 0,
    high_severity: 1,
    medium_severity: 2,
    low_severity: 1
  },
  {
    case_id: 'CASE-2026-004',
    name: 'NET-ALERT-881: DNS Tunneling Threat Indicator',
    description: 'Suricata NIDS triggered multiple alerts for high-frequency DNS query payloads pointing to unknown TLD.',
    status: 'IN_PROGRESS',
    risk_level: 'HIGH',
    assigned_to: 'Lead Analyst Sathwik',
    created_at: '2026-10-10 18:05:10',
    tenant_id: 'tenant-sec-ops',
    total_findings: 6,
    total_evidence: 4,
    critical_findings: 1,
    high_severity: 3,
    medium_severity: 2,
    low_severity: 0
  }
];

export const PREVIEW_MOCK_EVIDENCE = [
  {
    id: 'EVID-001',
    filename: 'mem_dump_srv_dc01.raw',
    artifact_type: 'RAM Memory Dump',
    size_mb: '16,384 MB',
    upload_timestamp: '2026-10-10 14:30:00',
    status: 'Ingested & Parsed',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  },
  {
    id: 'EVID-002',
    filename: 'suricata_nids_alerts_pcap.pcap',
    artifact_type: 'Network Capture',
    size_mb: '2,410 MB',
    upload_timestamp: '2026-10-10 14:45:12',
    status: 'Ingested & Parsed',
    hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
  },
  {
    id: 'EVID-003',
    filename: 'auth_domain_controller_evtx.evtx',
    artifact_type: 'Windows Event Logs',
    size_mb: '512 MB',
    upload_timestamp: '2026-10-10 15:02:40',
    status: 'Ingested & Parsed',
    hash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284ddd200126d90699'
  },
  {
    id: 'EVID-004',
    filename: 'exfil_stage_archive_backup.zip',
    artifact_type: 'Encrypted Zip Archive',
    size_mb: '4,100 MB',
    upload_timestamp: '2026-10-10 15:30:18',
    status: 'Sanitized',
    hash: '8f4e2c819a3b61029c78213456789012abcdef3456789012abcdef3456789012'
  },
  {
    id: 'EVID-005',
    filename: 'powershell_execution_history.log',
    artifact_type: 'Process Logs',
    size_mb: '48 MB',
    upload_timestamp: '2026-10-10 16:10:05',
    status: 'Ingested & Parsed',
    hash: '901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd'
  }
];

export const PREVIEW_MOCK_FINDINGS = [
  {
    finding_id: 'FINDING-001',
    severity: 'CRITICAL',
    confidence: 0.98,
    layer: 'network.nids',
    mitre_mapping: 'T1071 — Application Layer Protocol',
    fact: 'Suricata NIDS Alert: ET TROJAN Cobalt Strike Beacon HTTP outbound connection to 192.168.1.105 on TCP/443.',
    sanitized_fact: '[NIDS Alert] Cobalt Strike Beacon HTTP outbound traffic detected (Src: 10.0.4.12 → Dst: 192.168.1.105)',
    evidence_reference: ['suricata_nids_alerts_pcap.pcap'],
    timestamp: '2026-10-10 14:48:22'
  },
  {
    finding_id: 'FINDING-002',
    severity: 'CRITICAL',
    confidence: 0.95,
    layer: 'host.evtx',
    mitre_mapping: 'T1078 — Valid Accounts',
    fact: 'Windows Event 4624: Successful Logon for account admin_root from external workstation IP 192.168.1.105 via NTLMv2.',
    sanitized_fact: '[Auth Event 4624] External NTLMv2 administrator logon (Account: admin_root, Workstation: 192.168.1.105)',
    evidence_reference: ['auth_domain_controller_evtx.evtx'],
    timestamp: '2026-10-10 14:50:11'
  },
  {
    finding_id: 'FINDING-003',
    severity: 'HIGH',
    confidence: 0.92,
    layer: 'process.execution',
    mitre_mapping: 'T1059.001 — PowerShell Execution',
    fact: 'Process Creation Event 4688: powershell.exe executed encoded command: EncryptedPayload.ps1 -ExportVault -Destination 192.168.1.105',
    sanitized_fact: '[Process Exec] Encoded PowerShell script executed vault export toward external IP',
    evidence_reference: ['powershell_execution_history.log'],
    timestamp: '2026-10-10 15:05:44'
  },
  {
    finding_id: 'FINDING-004',
    severity: 'HIGH',
    confidence: 0.89,
    layer: 'memory.volatility',
    mitre_mapping: 'T1055 — Process Injection',
    fact: 'Volatility 3 malfind plugin: Injected RWX memory region detected inside lsass.exe pid: 742',
    sanitized_fact: '[Memory Analysis] Unbacked RWX memory segment detected in LSASS process space',
    evidence_reference: ['mem_dump_srv_dc01.raw'],
    timestamp: '2026-10-10 15:20:00'
  },
  {
    finding_id: 'FINDING-005',
    severity: 'MEDIUM',
    confidence: 0.85,
    layer: 'system.file',
    mitre_mapping: 'T1005 — Data from Local System',
    fact: 'File creation in C:\\Windows\\Temp\\fin_export_2026.zip containing 1,420 SQL backup records.',
    sanitized_fact: '[File System] Archive created in temp directory containing database exports',
    evidence_reference: ['exfil_stage_archive_backup.zip'],
    timestamp: '2026-10-10 15:35:10'
  },
  {
    finding_id: 'FINDING-006',
    severity: 'LOW',
    confidence: 0.90,
    layer: 'audit.gateway',
    mitre_mapping: 'T1027 — Obfuscated Files',
    fact: 'Sanitization Gateway verified: 14 PII entries (SSN & Credit Cards) automatically redacted from log stream.',
    sanitized_fact: '[Sanitization Gate] PII secrets scanned and masked automatically before rendering',
    evidence_reference: ['auth_domain_controller_evtx.evtx'],
    timestamp: '2026-10-10 16:00:00'
  }
];

export const PREVIEW_MOCK_AUDIT_LOGS = [
  {
    id: 'LOG-101',
    created_at: '2026-10-10 16:15:00',
    action: 'EVIDENCE_INGESTED',
    details: 'Artifact mem_dump_srv_dc01.raw uploaded and SHA-256 calculated.',
    created_by: 'Lead Analyst Sathwik'
  },
  {
    id: 'LOG-102',
    created_at: '2026-10-10 16:20:12',
    action: 'SANITIZATION_PASSED',
    details: 'Sanitization Gateway completed PII secret scanning with 0 unhandled leaks.',
    created_by: 'SYSTEM'
  },
  {
    id: 'LOG-103',
    created_at: '2026-10-10 16:35:40',
    action: 'FINDING_CORRELATED',
    details: 'Finding FINDING-001 correlated against MITRE ATT&CK T1071.',
    created_by: 'FIR Engine'
  },
  {
    id: 'LOG-104',
    created_at: '2026-10-10 17:00:05',
    action: 'DOSSIER_VERIFIED',
    details: 'Case CASE-2026-001 reviewed and signed by Senior Specialist Marcus.',
    created_by: 'Senior Specialist Marcus'
  }
];

export const PREVIEW_MOCK_GRAPH_NODES = [
  { id: 'node-case', label: 'CASE-2026-001', type: 'case', color: '#405D78' },
  { id: 'node-ip', label: '192.168.1.105', type: 'ip', color: '#111111' },
  { id: 'node-user', label: 'admin_root', type: 'user', color: '#304960' },
  { id: 'node-proc', label: 'powershell.exe', type: 'process', color: '#405D78' },
  { id: 'node-file', label: 'fin_export.zip', type: 'file', color: '#4B5563' },
];

export const PREVIEW_MOCK_CASE_NOTES = [
  {
    id: 'NOTE-001',
    author: 'Lead Analyst Sathwik',
    timestamp: '2026-10-10 15:45:00',
    content: 'Correlated Cobalt Strike beacon IP 192.168.1.105 with firewall egress logs. Confirmed 4.1 GB zip archive transferred via encrypted HTTPS tunnel.',
    category: 'Analysis Notes'
  },
  {
    id: 'NOTE-002',
    author: 'Senior Specialist Marcus',
    timestamp: '2026-10-10 16:10:20',
    content: 'Domain controller RAM dump analyzed with Volatility 3 malfind. Injected memory segment confirmed in LSASS PID 742. Escalated case risk to CRITICAL.',
    category: 'Forensic Investigation'
  },
  {
    id: 'NOTE-003',
    author: 'Auditor Inspector Vance',
    timestamp: '2026-10-10 16:30:15',
    content: 'Verified automated PII sanitization. SSN and Credit Card records masked prior to chain of custody export.',
    category: 'Audit & Compliance'
  }
];

export const PREVIEW_MOCK_SANITIZED_DATA = [
  {
    record_id: 'SAN-901',
    raw_snippet: 'User admin_root [SSN: 999-00-1234] logged in from 192.168.1.105 with CC 4532-XXXX-XXXX-9012',
    sanitized_snippet: 'User admin_root [SSN: ***-**-****] logged in from 192.168.1.105 with CC ****-****-****-9012',
    rule_applied: 'ARGUS PII Redaction Rule v2.4 (SSN + Credit Card Regex)',
    status: 'VERIFIED_CLEAN'
  },
  {
    record_id: 'SAN-902',
    raw_snippet: 'Exfiltration target: sftp://exfil-vault.ext/upload?key=SECRET_API_KEY_99218',
    sanitized_snippet: 'Exfiltration target: sftp://exfil-vault.ext/upload?key=[REDACTED_API_KEY]',
    rule_applied: 'ARGUS Credential Masking Engine',
    status: 'VERIFIED_CLEAN'
  }
];

export const PREVIEW_MOCK_SETTINGS = {
  tenant_name: 'ARGUS Corporate Forensics Unit',
  environment: 'Production Gateway (SHA-256 Multi-Tenant)',
  pii_masking_enabled: true,
  auto_correlation_engine: true,
  mitre_attck_mapping_version: 'v14.1',
  max_evidence_upload_gb: 32,
  audit_logging_retention_days: 365
};

export const PREVIEW_MOCK_EMPLOYEES = [
  { id: 'EMP-01', name: 'Sathwik Sai', role: 'Lead Forensics Lead', department: 'SecOps', risk_score: 'LOW' },
  { id: 'EMP-02', name: 'Marcus Vance', role: 'Senior Malware Specialist', department: 'Threat Intel', risk_score: 'MEDIUM' },
  { id: 'EMP-03', name: 'Elena Rostova', role: 'System Administrator', department: 'IT Infrastructure', risk_score: 'HIGH' }
];

