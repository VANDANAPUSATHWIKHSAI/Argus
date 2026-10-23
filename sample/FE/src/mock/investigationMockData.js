// ARGUS Forensic Mock Data Store — Shared across Design Templates & Pages

export const MOCK_CASES = [
  {
    id: 'ARGUS-2026-0892',
    case_id: 'ARGUS_01',
    name: 'FIN7 Phishing & Credential Access',
    incident_type: 'Ransomware & Credential Theft',
    status: 'ACTIVE',
    severity: 'CRITICAL',
    created_at: '2026-10-06T08:15:00Z',
    assignedTo: 'Sarah Connor',
    analyst_name: 'Sarah Connor (Senior Analyst)',
    senior_analyst: 'Elena Vance (Lead)',
    description: 'Spearphishing email with weaponized Excel document triggered in-memory PowerShell download cradle, leading to LSASS dumping and C2 beaconing.',
    threat_actor: 'FIN7 / Carbanak Group',
    affected_hosts: ['WIN-SRV-AD01', 'WORKSTATION-412', 'FINANCE-PC09'],
    investigation_progress: {
      evidence_intake: 100,
      deterministic_parsing: 100,
      fir_grounding: 100,
      ai_correlation: 85,
      verification: 75,
      report_generation: 40
    }
  },
  {
    id: 'ARGUS-2026-0893',
    case_id: 'ARGUS_02',
    name: 'BlackCat / ALPHV Lateral Movement',
    incident_type: 'Ransomware Outbreak',
    status: 'IN_REVIEW',
    severity: 'HIGH',
    created_at: '2026-10-05T14:30:00Z',
    assignedTo: 'Alex Rivera',
    analyst_name: 'Alex Rivera (Analyst)',
    senior_analyst: 'Sarah Connor (Lead)',
    description: 'Compromised VPN credentials utilized to establish persistence via WMI event subscription and stage data exfiltration.',
    threat_actor: 'ALPHV / BlackCat Affiliate',
    affected_hosts: ['DC01-PRIMARY', 'FILESRV-02'],
    investigation_progress: {
      evidence_intake: 100,
      deterministic_parsing: 100,
      fir_grounding: 90,
      ai_correlation: 70,
      verification: 60,
      report_generation: 20
    }
  },
  {
    id: 'ARGUS-2026-0880',
    case_id: 'ARGUS_03',
    name: 'Insider Exfiltration via DNS Tunnel',
    incident_type: 'Data Exfiltration',
    status: 'CLOSED',
    severity: 'MEDIUM',
    created_at: '2026-09-28T11:00:00Z',
    assignedTo: 'Marcus Chen',
    analyst_name: 'Marcus Chen (Senior)',
    senior_analyst: 'Sarah Connor (Lead)',
    description: 'High entropy DNS queries detected from developer endpoint staging proprietary source code archives.',
    threat_actor: 'Disgruntled Insider',
    affected_hosts: ['DEV-LAPTOP-108'],
    investigation_progress: {
      evidence_intake: 100,
      deterministic_parsing: 100,
      fir_grounding: 100,
      ai_correlation: 100,
      verification: 100,
      report_generation: 100
    }
  }
];

export const MOCK_EVIDENCE_FILES = [
  {
    id: 'EV-001',
    evidence_id: 'EVID-SYS-001',
    case_id: 'ARGUS_01',
    fileName: 'Sysmon-Operational.evtx',
    filename: 'Microsoft-Windows-Sysmon-Operational.evtx',
    fileType: 'EVTX',
    type: 'EVTX',
    fileSize: '141.7 MB',
    size_formatted: '141.7 MB',
    sha256: '9f83a21d5c7b4e8a1f6e3d2c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a',
    uploadedBy: 'Sarah Connor',
    uploaded_by: 'Sarah Connor',
    rfc3161Timestamp: '2026-10-06 08:20:12 UTC',
    upload_timestamp: '2026-10-06T08:20:12Z',
    chainOfCustodyStatus: 'RFC 3161 Verified',
    status: 'Processed',
    rfc3161_verified: true,
    tsa_authority: 'FreeTSA Global RFC 3161 Timestamping',
    parsedArtifacts: 1420,
    extracted_artifacts_count: 1420,
    findings_count: 4,
    sourceHost: 'WORKSTATION-412',
    source_host: 'WORKSTATION-412'
  },
  {
    id: 'EV-002',
    evidence_id: 'EVID-NET-002',
    case_id: 'ARGUS_01',
    fileName: 'perimeter_egress_c2.pcap',
    filename: 'perimeter_egress_c2.pcap',
    fileType: 'PCAP',
    type: 'PCAP',
    fileSize: '409.0 MB',
    size_formatted: '409.0 MB',
    sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e',
    uploadedBy: 'Sarah Connor',
    uploaded_by: 'Sarah Connor',
    rfc3161Timestamp: '2026-10-06 08:25:44 UTC',
    upload_timestamp: '2026-10-06T08:25:44Z',
    chainOfCustodyStatus: 'RFC 3161 Verified',
    status: 'Processed',
    rfc3161_verified: true,
    tsa_authority: 'FreeTSA Global RFC 3161 Timestamping',
    parsedArtifacts: 3890,
    extracted_artifacts_count: 3890,
    findings_count: 3,
    sourceHost: 'FIREWALL-EDGE01',
    source_host: 'FIREWALL-EDGE01'
  },
  {
    id: 'EV-003',
    evidence_id: 'EVID-MEM-003',
    case_id: 'ARGUS_01',
    fileName: 'workstation412_memory.raw',
    filename: 'workstation412_memory.raw',
    fileType: 'Memory Dump',
    type: 'Memory Dump',
    fileSize: '8.00 GB',
    size_formatted: '8.00 GB',
    sha256: '7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d',
    uploadedBy: 'Sarah Connor',
    uploaded_by: 'Sarah Connor',
    rfc3161Timestamp: '2026-10-06 08:42:01 UTC',
    upload_timestamp: '2026-10-06T08:42:01Z',
    chainOfCustodyStatus: 'RFC 3161 Verified',
    status: 'Processed',
    rfc3161_verified: true,
    tsa_authority: 'FreeTSA Global RFC 3161 Timestamping',
    parsedArtifacts: 854,
    extracted_artifacts_count: 854,
    findings_count: 2,
    sourceHost: 'WORKSTATION-412',
    source_host: 'WORKSTATION-412'
  },
  {
    id: 'EV-004',
    evidence_id: 'EVID-EML-004',
    case_id: 'ARGUS_01',
    fileName: 'invoice_october_statement.eml',
    filename: 'invoice_october_statement.eml',
    fileType: 'Email (EML)',
    type: 'Email (EML)',
    fileSize: '1.39 MB',
    size_formatted: '1.39 MB',
    sha256: '4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a',
    uploadedBy: 'Sarah Connor',
    uploaded_by: 'Sarah Connor',
    rfc3161Timestamp: '2026-10-06 08:18:30 UTC',
    upload_timestamp: '2026-10-06T08:18:30Z',
    chainOfCustodyStatus: 'RFC 3161 Verified',
    status: 'Processed',
    rfc3161_verified: true,
    tsa_authority: 'FreeTSA Global RFC 3161 Timestamping',
    parsedArtifacts: 32,
    extracted_artifacts_count: 32,
    findings_count: 1,
    sourceHost: 'MAIL-GATEWAY',
    source_host: 'MAIL-GATEWAY'
  },
  {
    id: 'EV-005',
    evidence_id: 'EVID-REG-005',
    case_id: 'ARGUS_01',
    fileName: 'SYSTEM_hive.hiv',
    filename: 'SYSTEM_hive.hiv',
    fileType: 'Registry Hive',
    type: 'Registry Hive',
    fileSize: '27.1 MB',
    size_formatted: '27.1 MB',
    sha256: '2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c',
    uploadedBy: 'Sarah Connor',
    uploaded_by: 'Sarah Connor',
    rfc3161Timestamp: '2026-10-06 09:05:10 UTC',
    upload_timestamp: '2026-10-06T09:05:10Z',
    chainOfCustodyStatus: 'RFC 3161 Verified',
    status: 'Processed',
    rfc3161_verified: true,
    tsa_authority: 'FreeTSA Global RFC 3161 Timestamping',
    parsedArtifacts: 412,
    extracted_artifacts_count: 412,
    findings_count: 2,
    sourceHost: 'WORKSTATION-412',
    source_host: 'WORKSTATION-412'
  }
];

export const MOCK_FIR_FINDINGS = [
  {
    id: 'F-101',
    finding_id: 'F-101',
    case_id: 'ARGUS_01',
    layer: 'Endpoint',
    title: 'Obfuscated PowerShell Execution Spawned by Excel',
    fact: 'Process execution: EXCEL.EXE spawned powershell.exe with base64 encoded arguments (CommandLine: powershell.exe -NoP -NonI -W Hidden -Enc SUVYKE5ldy1PYmplY3Q...).',
    rawText: 'Process execution: EXCEL.EXE (PID 1894) spawned powershell.exe (PID 4120) with base64 encoded arguments on host WORKSTATION-412 for user FINANCE\\jsmith.',
    sanitizedFact: 'Process execution: EXCEL.EXE spawned powershell.exe with base64 encoded arguments [PAYLOAD REDACTED FOR SANITIZATION].',
    sanitized_fact: 'Process execution: EXCEL.EXE spawned powershell.exe with base64 encoded arguments [PAYLOAD REDACTED FOR SANITIZATION].',
    confidence: 100,
    severity: 'CRITICAL',
    mitreTechnique: 'T1566.001 ➔ T1059.001',
    mitre_mapping: 'T1566.001 (Spearphishing Attachment) ➔ T1059.001 (PowerShell)',
    sourceEvidence: 'EV-001',
    source_evidence: 'EVID-SYS-001',
    evidence_reference: ['EVID-SYS-001', 'EVID-EML-004'],
    sourcePage: 1,
    timestamp: '2026-10-06T08:14:22Z',
    reviewStatus: 'PROMOTED',
    review_status: 'analyst_confirmed',
    makerChecker: {
      status: 'APPROVED',
      promotedBy: 'Sarah Connor (Senior Lead)',
      approvedAt: '2026-10-06 08:30:00'
    }
  },
  {
    id: 'F-102',
    finding_id: 'F-102',
    case_id: 'ARGUS_01',
    layer: 'Network',
    title: 'Encrypted High-Frequency TLS C2 Beaconing',
    fact: 'High-frequency TLS beaconing (interval 45s +/- 3s jitter) established to external IP 198.51.100.4 on port 443 with self-signed certificate.',
    rawText: 'TLS connection established from 192.168.4.12:49821 to 198.51.100.4:443 matching Cobalt Strike default beacon profile with self-signed certificate "update-service-cdn.org".',
    sanitizedFact: 'High-frequency TLS beaconing established to external IP 198.51.100.4:443 with self-signed certificate.',
    sanitized_fact: 'High-frequency TLS beaconing established to external IP 198.51.100.4:443 with self-signed certificate.',
    confidence: 98,
    severity: 'CRITICAL',
    mitreTechnique: 'T1071.001 ➔ T1573',
    mitre_mapping: 'T1071.001 (Web Protocols) ➔ T1573 (Encrypted Channel)',
    sourceEvidence: 'EV-002',
    source_evidence: 'EVID-NET-002',
    evidence_reference: ['EVID-NET-002'],
    sourcePage: 4,
    timestamp: '2026-10-06T08:16:05Z',
    reviewStatus: 'PROMOTED',
    review_status: 'analyst_confirmed',
    makerChecker: {
      status: 'APPROVED',
      promotedBy: 'Sarah Connor (Senior Lead)',
      approvedAt: '2026-10-06 08:35:00'
    }
  },
  {
    id: 'F-103',
    finding_id: 'F-103',
    case_id: 'ARGUS_01',
    layer: 'Memory',
    title: 'LSASS Memory Injection (Mimikatz Signature)',
    fact: 'Volatility 3 malfind detected injected unbacked executable memory segment with PAGE_EXECUTE_READWRITE permissions inside lsass.exe (PID 672).',
    rawText: 'Injected unbacked thread found in lsass.exe PID 672 at address 0x7ffb140000 matching YARA rule "Mimikatz_Memory_Strings" extracting NTLM hashes.',
    sanitizedFact: 'Injected executable memory segment detected inside lsass.exe (PID 672) matching credential dumper signature.',
    sanitized_fact: 'Injected executable memory segment detected inside lsass.exe (PID 672) matching credential dumper signature.',
    confidence: 100,
    severity: 'CRITICAL',
    mitreTechnique: 'T1003.001 ➔ T1055.001',
    mitre_mapping: 'T1003.001 (LSASS Memory Dumping) ➔ T1055.001 (Dynamic-link Library Injection)',
    sourceEvidence: 'EV-003',
    source_evidence: 'EVID-MEM-003',
    evidence_reference: ['EVID-MEM-003', 'EVID-SYS-001'],
    sourcePage: 12,
    timestamp: '2026-10-06T08:22:15Z',
    reviewStatus: 'PENDING_REVIEW',
    review_status: 'pending_review',
    makerChecker: {
      status: 'PENDING',
      promotedBy: null,
      approvedAt: null
    }
  },
  {
    id: 'F-104',
    finding_id: 'F-104',
    case_id: 'ARGUS_01',
    layer: 'Registry',
    title: 'Registry Run Key Persistence Mechanism',
    fact: 'Registry persistence installed: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry "SecurityHealthSystray" pointing to "C:\\Users\\Public\\svchost_update.exe".',
    rawText: 'Registry key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified with value "SecurityHealthSystray" -> "C:\\Users\\Public\\svchost_update.exe".',
    sanitizedFact: 'Registry persistence installed under CurrentVersion\\Run pointing to "C:\\Users\\Public\\svchost_update.exe".',
    sanitized_fact: 'Registry persistence installed under CurrentVersion\\Run pointing to "C:\\Users\\Public\\svchost_update.exe".',
    confidence: 95,
    severity: 'HIGH',
    mitreTechnique: 'T1547.001',
    mitre_mapping: 'T1547.001 (Registry Run Keys / Startup Folder)',
    sourceEvidence: 'EV-005',
    source_evidence: 'EVID-REG-005',
    evidence_reference: ['EVID-REG-005', 'EVID-SYS-001'],
    sourcePage: 2,
    timestamp: '2026-10-06T08:29:40Z',
    reviewStatus: 'PENDING_REVIEW',
    review_status: 'pending_review',
    makerChecker: {
      status: 'PENDING',
      promotedBy: null,
      approvedAt: null
    }
  },
  {
    id: 'F-105',
    finding_id: 'F-105',
    case_id: 'ARGUS_01',
    layer: 'Endpoint',
    title: 'Volume Shadow Copies Purged via VSSadmin',
    fact: 'VSSadmin shadow copy deletion command executed: "vssadmin.exe delete shadows /all /quiet" to impede recovery.',
    rawText: 'Command line "vssadmin.exe delete shadows /all /quiet" executed by NT AUTHORITY\\SYSTEM on host WORKSTATION-412 (PID 5812).',
    sanitizedFact: 'VSSadmin shadow copy deletion executed: "vssadmin.exe delete shadows /all /quiet".',
    sanitized_fact: 'VSSadmin shadow copy deletion executed: "vssadmin.exe delete shadows /all /quiet".',
    confidence: 100,
    severity: 'HIGH',
    mitreTechnique: 'T1490',
    mitre_mapping: 'T1490 (Inhibit System Recovery)',
    sourceEvidence: 'EV-001',
    source_evidence: 'EVID-SYS-001',
    evidence_reference: ['EVID-SYS-001'],
    sourcePage: 3,
    timestamp: '2026-10-06T08:34:10Z',
    reviewStatus: 'PENDING_REVIEW',
    review_status: 'pending_review',
    makerChecker: {
      status: 'PENDING',
      promotedBy: null,
      approvedAt: null
    }
  }
];

export const MOCK_AI_CLAIMS = [
  {
    id: 'CLAIM-01',
    claim_id: 'CLAIM-01',
    findingId: 'F-101',
    title: 'Initial Access via Weaponized Phishing E-Mail',
    claimText: 'The attacker gained initial access to WORKSTATION-412 via an incoming phishing email with weaponized Excel spreadsheet macro, which spawned an obfuscated PowerShell download cradle.',
    claim: 'The attacker gained initial access to WORKSTATION-412 via an incoming phishing email with weaponized Excel spreadsheet macro, which spawned an obfuscated PowerShell download cradle.',
    groundedPassage: 'Sysmon Event ID 1: ParentImage: C:\\Program Files\\Microsoft Office\\EXCEL.EXE -> Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Enc SUVY...',
    entailmentScore: 0.97,
    confidence_score: 0.98,
    sourceDoc: 'Sysmon-Operational.evtx',
    mitre_tactics: ['Initial Access', 'Execution'],
    verification: {
      verified: true,
      entailment_score: 0.97,
      model_checker: 'DeBERTa-v3-large-MNLI'
    }
  },
  {
    id: 'CLAIM-02',
    claim_id: 'CLAIM-02',
    findingId: 'F-102',
    title: 'Command & Control Establishment',
    claimText: 'The spawned PowerShell process established an encrypted TLS C2 channel to 198.51.100.4:443 with 45-second jitter intervals for interactive operator control.',
    claim: 'The spawned PowerShell process established an encrypted TLS C2 channel to 198.51.100.4:443 with 45-second jitter intervals for interactive operator control.',
    groundedPassage: 'Zeek ssl.log: 192.168.4.12:49821 -> 198.51.100.4:443 subject: CN=update-service-cdn.org periodic 45s flow.',
    entailmentScore: 0.94,
    confidence_score: 0.95,
    sourceDoc: 'perimeter_egress_c2.pcap',
    mitre_tactics: ['Command and Control'],
    verification: {
      verified: true,
      entailment_score: 0.94,
      model_checker: 'DeBERTa-v3-large-MNLI'
    }
  },
  {
    id: 'CLAIM-03',
    claim_id: 'CLAIM-03',
    findingId: 'F-103',
    title: 'In-Memory LSASS Credential Dumping (Mimikatz)',
    claimText: 'The operator executed unbacked shellcode injection directly into the LSASS address space (PID 672) to extract cleartext domain credentials and Kerberos tickets from memory.',
    claim: 'The operator executed unbacked shellcode injection directly into the LSASS address space (PID 672) to extract cleartext domain credentials and Kerberos tickets from memory.',
    groundedPassage: 'Volatility 3 malfind: PID 672 lsass.exe unbacked VAD 0x7ffb140000 PAGE_EXECUTE_READWRITE bytes: 4d 5a 90 00...',
    entailmentScore: 0.98,
    confidence_score: 0.99,
    sourceDoc: 'workstation412_memory.raw',
    mitre_tactics: ['Credential Access', 'Defense Evasion'],
    verification: {
      verified: true,
      entailment_score: 0.98,
      model_checker: 'DeBERTa-v3-large-MNLI'
    }
  },
  {
    id: 'CLAIM-04',
    claim_id: 'CLAIM-04',
    findingId: 'F-104',
    title: 'Persistence & Impending Ransomware Staging',
    claimText: 'Following credential harvesting, persistence was anchored via HKLM Run keys while Volume Shadow Copies were purged in preparation for network-wide ransomware deployment.',
    claim: 'Following credential harvesting, persistence was anchored via HKLM Run keys while Volume Shadow Copies were purged in preparation for network-wide ransomware deployment.',
    groundedPassage: 'RegRipper: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> SecurityHealthSystray: C:\\Users\\Public\\svchost_update.exe',
    entailmentScore: 0.91,
    confidence_score: 0.92,
    sourceDoc: 'SYSTEM_hive.hiv',
    mitre_tactics: ['Persistence', 'Impact'],
    verification: {
      verified: true,
      entailment_score: 0.91,
      model_checker: 'DeBERTa-v3-large-MNLI'
    }
  }
];

export const MOCK_TIMELINE_EVENTS = [
  {
    id: 'TL-01',
    event_id: 'TL-01',
    timestamp: '2026-10-06 08:14:10',
    time: '2026-10-06 08:14:10',
    actor: 'MAIL-GATEWAY',
    host: 'MAIL-GW01',
    category: 'Initial Access',
    severity: 'HIGH',
    title: 'Phishing Email Delivered',
    event: 'Phishing Email Delivered',
    description: 'Email received with attachment "invoice_statement.xlsm" sent from spoofed vendor domain.',
    details: 'Email received with attachment "invoice_statement.xlsm" sent from spoofed vendor domain.',
    observable: 'invoice_statement.xlsm (SHA-256: 4f5a...)'
  },
  {
    id: 'TL-02',
    event_id: 'TL-02',
    timestamp: '2026-10-06 08:14:22',
    time: '2026-10-06 08:14:22',
    actor: 'WORKSTATION-412',
    host: 'WORKSTATION-412',
    category: 'Execution',
    severity: 'CRITICAL',
    title: 'Macro Spawns Obfuscated PowerShell',
    event: 'Macro Spawns Obfuscated PowerShell',
    description: 'EXCEL.EXE (PID 1894) launched powershell.exe with hidden window and base64 download cradle.',
    details: 'EXCEL.EXE (PID 1894) launched powershell.exe with hidden window and base64 download cradle.',
    observable: 'PID 4120 • powershell.exe -Enc SUVY...'
  },
  {
    id: 'TL-03',
    event_id: 'TL-03',
    timestamp: '2026-10-06 08:16:05',
    time: '2026-10-06 08:16:05',
    actor: 'FIREWALL-EDGE01',
    host: 'FIREWALL-EDGE01',
    category: 'Command & Control',
    severity: 'CRITICAL',
    title: 'Encrypted C2 Channel Established',
    event: 'Encrypted C2 Channel Established',
    description: 'TCP handshake and TLS 1.3 tunnel opened to 198.51.100.4:443. Periodic beaconing initiated.',
    details: 'TCP handshake and TLS 1.3 tunnel opened to 198.51.100.4:443. Periodic beaconing initiated.',
    observable: '198.51.100.4:443 • TLS 1.3 CN=update-service-cdn.org'
  },
  {
    id: 'TL-04',
    event_id: 'TL-04',
    timestamp: '2026-10-06 08:22:15',
    time: '2026-10-06 08:22:15',
    actor: 'WORKSTATION-412',
    host: 'WORKSTATION-412',
    category: 'Credential Access',
    severity: 'CRITICAL',
    title: 'LSASS Memory Injection (Mimikatz)',
    event: 'LSASS Memory Injection (Mimikatz)',
    description: 'Unbacked RWX memory segment injected into lsass.exe (PID 672). Password hashes extracted.',
    details: 'Unbacked RWX memory segment injected into lsass.exe (PID 672). Password hashes extracted.',
    observable: 'lsass.exe (PID 672) • VAD: 0x7ffb140000'
  },
  {
    id: 'TL-05',
    event_id: 'TL-05',
    timestamp: '2026-10-06 08:29:40',
    time: '2026-10-06 08:29:40',
    actor: 'WORKSTATION-412',
    host: 'WORKSTATION-412',
    category: 'Persistence',
    severity: 'HIGH',
    title: 'Registry Run Key Persistence',
    event: 'Registry Run Key Persistence',
    description: 'HKLM Run key "SecurityHealthSystray" created pointing to C:\\Users\\Public\\svchost_update.exe.',
    details: 'HKLM Run key "SecurityHealthSystray" created pointing to C:\\Users\\Public\\svchost_update.exe.',
    observable: 'HKLM\\...\\Run: SecurityHealthSystray'
  },
  {
    id: 'TL-06',
    event_id: 'TL-06',
    timestamp: '2026-10-06 08:34:10',
    time: '2026-10-06 08:34:10',
    actor: 'WORKSTATION-412',
    host: 'WORKSTATION-412',
    category: 'Defense Evasion',
    severity: 'HIGH',
    title: 'Shadow Copies Purged',
    event: 'Shadow Copies Purged',
    description: 'vssadmin.exe executed by SYSTEM deleting all volume shadow copies to inhibit rollback.',
    details: 'vssadmin.exe executed by SYSTEM deleting all volume shadow copies to inhibit rollback.',
    observable: 'vssadmin.exe delete shadows /all /quiet'
  }
];

export const MOCK_AUDIT_EVENTS = [
  {
    id: 'AUD-01',
    timestamp: '2026-10-06 08:15:00 UTC',
    actor: 'Admin User',
    user: 'Admin User',
    role: 'System Administrator',
    action: 'Created Case',
    resource: 'ARGUS_01 ("FIN7 Phishing & Credential Access")',
    details: 'Assigned Sarah Connor as lead analyst and Elena Vance as reviewer.'
  },
  {
    id: 'AUD-02',
    timestamp: '2026-10-06 08:20:12 UTC',
    actor: 'Sarah Connor',
    user: 'Sarah Connor',
    role: 'Senior Lead Analyst',
    action: 'Uploaded Evidence',
    resource: 'Microsoft-Windows-Sysmon-Operational.evtx',
    details: 'SHA-256 seal computed and verified via FreeTSA RFC 3161.'
  },
  {
    id: 'AUD-03',
    timestamp: '2026-10-06 08:26:00 UTC',
    actor: 'System Pipeline',
    user: 'Sanitization Engine',
    role: 'Automated Gateway',
    action: 'Generated FIR Findings',
    resource: 'FIR Findings F-101 to F-105',
    details: 'Sanitization Gateway passed with 0 prompt injection alerts.'
  },
  {
    id: 'AUD-04',
    timestamp: '2026-10-06 09:15:00 UTC',
    actor: 'Elena Vance',
    user: 'Elena Vance',
    role: 'Senior Reviewer',
    action: 'Confirmed Finding',
    resource: 'Finding F-103 (LSASS Memory Injection)',
    details: 'Maker-checker pre-validation approved.'
  }
];

export const MOCK_CASE_NOTES = [
  {
    id: 'NOTE-01',
    note_id: 'NOTE-01',
    case_id: 'ARGUS_01',
    title: 'Initial Phishing Attribution',
    content: 'Email headers confirm SPF pass on spoofed vendor domain. Base64 payload in Excel macro calls out to external infrastructure.',
    author: 'Sarah Connor',
    role: 'Lead Analyst',
    timestamp: 'Today, 08:45 AM',
    created_at: '2026-10-06T08:45:00Z'
  },
  {
    id: 'NOTE-02',
    note_id: 'NOTE-02',
    case_id: 'ARGUS_01',
    title: 'LSASS Dump Confirmed via Malfind',
    content: 'Memory analysis confirms injected thread in LSASS. Recommending immediate domain-wide password resets for compromised finance tier accounts.',
    author: 'Elena Vance',
    role: 'Senior Reviewer',
    timestamp: 'Today, 09:12 AM',
    created_at: '2026-10-06T09:12:00Z'
  }
];

export const MOCK_TOPOLOGY_NODES = [
  { id: 'N-HOST-01', label: 'WORKSTATION-412', type: 'host', riskLevel: 'HIGH', metadata: 'Windows 11 Enterprise (192.168.1.105)' },
  { id: 'N-PROC-01', label: 'powershell.exe', type: 'process', riskLevel: 'CRITICAL', metadata: 'PID: 4892 • Encoded Command Execution' },
  { id: 'N-MEM-01', label: 'LSASS Dump', type: 'artifact', riskLevel: 'CRITICAL', metadata: 'Process MiniDump • 42 MB' },
  { id: 'N-NET-01', label: '198.51.100.42:443', type: 'network', riskLevel: 'HIGH', metadata: 'External C2 Server • Cobalt Strike' },
  { id: 'N-EVID-01', label: 'Sysmon-Operational.evtx', type: 'evidence', riskLevel: 'LOW', metadata: '14,200 Events • SHA-256 Verified' }
];

// Compatibility aliases
export const MOCK_FINDINGS = MOCK_FIR_FINDINGS;
export const MOCK_AUDIT_LOGS = MOCK_AUDIT_EVENTS;
