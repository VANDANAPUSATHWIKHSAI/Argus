// ==========================================================================
// ARGUS Forensic Data Store & Dynamic Swarm Telemetry
// ==========================================================================

// Initial Pristine System State (0 Cases, All Agents & Pipelines Idle)
window.ARGUS_DATA = {
  // Currently Active Investigation Workspace (null on startup)
  activeCase: null,

  // Historical Closed Investigations (0 on startup)
  historyCases: [],

  // Pipeline Stages (All 8 Stages Idle on startup)
  pipelineStages: [
    { id: "created", name: "Case Created", status: "idle", description: "Investigation parameters established" },
    { id: "evidence", name: "Evidence Uploaded", status: "idle", description: "Artifacts attached and verified" },
    { id: "infrastructure", name: "Infrastructure Enclave", status: "idle", description: "SHA256, AES-256 HSM verification" },
    { id: "preprocessing", name: "Evidence Preprocessing", status: "idle", description: "Data extraction & normalization" },
    { id: "analysis", name: "Forensic Analysis", status: "idle", description: "Deterministic engines & AI Swarm" },
    { id: "review", name: "Senior Review", status: "idle", description: "Confidence gate & Senior signoff" },
    { id: "report", name: "Report Generation", status: "idle", description: "Multi-audience synthesis" },
    { id: "closed", name: "Case Closure", status: "idle", description: "Finalized and moved to history" }
  ],

  // AI Agent Swarm Data (All 7 Agents in Idle Status)
  agents: [
    {
      id: "agent-1",
      number: "1",
      name: "Artifact Classifier & Triage Agent",
      role: "Deterministic Triage & Categorization",
      status: "Idle",
      model: "ARGUS-Triage-v4",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Waiting for forensic evidence submission to begin automated categorization.",
      findings: [],
      logs: []
    },
    {
      id: "agent-2",
      number: "2",
      name: "Volatility Memory Extractor",
      role: "RAM & Kernel Space Deep Inspection",
      status: "Idle",
      model: "ARGUS-MemoryEngine-v3",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Waiting for Agent 1 triage completion to begin memory structure inspection.",
      findings: [],
      logs: []
    },
    {
      id: "agent-3",
      number: "3",
      name: "Attack Reconstruction Engine",
      role: "Causal Execution Graph & Kill-Chain Builder",
      status: "Idle",
      model: "DeepSeek-R1-Forensic-Specialist",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Waiting for memory and timeline artifacts to synthesize causal attack graphs.",
      findings: [],
      logs: []
    },
    {
      id: "agent-4",
      number: "4",
      name: "Lateral Movement & Pivoting Detector",
      role: "Kerberos & RPC Telemetry Analysis",
      status: "Idle",
      model: "ARGUS-LateralMove-v2",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Staged to inspect domain login events and lateral pivot anomalies.",
      findings: [],
      logs: []
    },
    {
      id: "agent-5a",
      number: "5a",
      name: "Threat Intel & IOC Correlator",
      role: "OSINT & Threat Actor Attribution",
      status: "Idle",
      model: "ARGUS-IntelFeeds-v5",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Staged to correlate network IOCs and hashes against adversary feeds.",
      findings: [],
      logs: []
    },
    {
      id: "agent-5b",
      number: "5b",
      name: "C2 & Exfiltration Tracer",
      role: "Network Flow & DNS Tunneling Inspector",
      status: "Idle",
      model: "ARGUS-NetForensics-v2",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Staged to calculate exfiltration metrics and TLS beacon frequencies.",
      findings: [],
      logs: []
    },
    {
      id: "agent-6",
      number: "6",
      name: "Risk & Impact Evaluator",
      role: "Business Impact, ISS & ICS Computation",
      status: "Idle",
      model: "ARGUS-RiskEngine-v4",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Staged to evaluate Impact Severity Score (ISS) and enterprise blast radius.",
      findings: [],
      logs: []
    },
    {
      id: "agent-7",
      number: "7",
      name: "Multi-Audience Report Synthesizer",
      role: "Executive, Technical & Customer Report Generator",
      status: "Idle",
      model: "Gemini-1.5-Pro-Forensics",
      confidence: "Pending",
      executionTime: "--",
      summary: "Idle. Staged to synthesize finalized executive briefings and forensic bundles.",
      findings: [],
      logs: []
    }
  ],

  // Live Progress Monitor Details for Active Investigation
  progressMonitor: {
    infrastructure: {
      status: "Idle",
      sha256: "--",
      encryption: "AES-256-GCM HSM",
      timestamping: "RFC 3161 Certified",
      integrityStatus: "Awaiting Verification"
    },
    preprocessing: {
      status: "Idle",
      artifactsExtracted: "0",
      fcrRecords: "0",
      parserEngines: "Rust Plaso Bridge + Volatility 3 Core",
      mftRecords: "0 parsed",
      registryHives: "SAM, SYSTEM, SOFTWARE"
    },
    analysisLayer: [
      { name: "Log Analysis", status: "Idle", icon: "clock", duration: "--", events: "Awaiting execution" },
      { name: "Network Analysis", status: "Idle", icon: "clock", duration: "--", events: "Awaiting execution" },
      { name: "Memory Analysis", status: "Idle", icon: "clock", duration: "--", events: "Awaiting execution" },
      { name: "Endpoint Analysis", status: "Idle", icon: "clock", duration: "--", events: "Awaiting execution" },
      { name: "Email Analysis", status: "Idle", icon: "clock", duration: "--", events: "Awaiting execution" }
    ]
  },

  findings: null,
  graphData: null,
  riskAssessment: null,
  immediateActions: [],
  humanReview: null,
  reports: null,
  auditLogs: []
};

// ==========================================================================
// FORENSIC CASE EXECUTION TEMPLATES (Loaded during live investigation simulation)
// ==========================================================================
window.ARGUS_CASE_TEMPLATES = {
  activeTemplate: {
    infrastructure: {
      status: "Completed",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      encryption: "AES-256-GCM Hardware Security Module",
      timestamping: "RFC 3161 Trusted Time Authority (DigiCert)",
      integrityStatus: "Verified 100% Unaltered"
    },
    preprocessing: {
      status: "Completed",
      artifactsExtracted: "12,430",
      fcrRecords: "5,282",
      parserEngines: "Rust Plaso Bridge + Volatility 3 Core",
      mftRecords: "482,900 parsed in 3.2s",
      registryHives: "SAM, SYSTEM, SOFTWARE, NTUSER.DAT"
    },
    analysisLayer: [
      { name: "Log Analysis", status: "Completed", icon: "check-circle", duration: "1.4s", events: "412,900 EVTX records evaluated" },
      { name: "Network Analysis", status: "Completed", icon: "check-circle", duration: "2.8s", events: "8.4 GB PCAP & Zeek flow logs triaged" },
      { name: "Memory Analysis", status: "Completed", icon: "check-circle", duration: "3.9s", events: "VAD tree traversal & code injection scan" },
      { name: "Endpoint Analysis", status: "Completed", icon: "check-circle", duration: "1.8s", events: "Prefetch, Shimcache, Amcache correlated" },
      { name: "Email Analysis", status: "Completed", icon: "check-circle", duration: "1.1s", events: "MIME header DKIM/SPF & attachment sandboxed" }
    ],

    // Agent Full Results after execution
    agentResults: {
      "agent-1": {
        status: "Completed",
        confidence: "99.1%",
        executionTime: "3.4s",
        summary: "Classified 12,430 raw forensic artifacts across 6 distinct sub-categories. Identified 14 suspicious PE headers and 2 obfuscated scripts.",
        findings: [
          "Identified malicious ISO container: 'invoice_march2026.iso'",
          "Flagged hidden LNK file executing cmd.exe with arguments",
          "Categorized EVTX Security Log for credential extraction attempts"
        ],
        logs: [
          "[09:12:48] Initializing classifier daemon on isolated GPU cluster node 01...",
          "[09:12:50] Intake of 12,430 artifacts completed. Mapping magic bytes...",
          "[09:12:51] Extracted 14 portable executables and 8 script blocks for sandbox inspection.",
          "[09:12:52] Classification matrix established. Handing off FIR to Agent 2."
        ]
      },
      "agent-2": {
        status: "Completed",
        confidence: "96.4%",
        executionTime: "7.1s",
        summary: "Analyzed 16GB memory dump (DESKTOP-WK88.raw). Discovered injected hollow process in svchost.exe (PID 4892) with anomalous RWX memory permissions.",
        findings: [
          "Malicious shellcode injected in svchost.exe PID 4892 (VAD protection: PAGE_EXECUTE_READWRITE)",
          "LSASS memory handle opened by suspicious non-system process (PID 5120)",
          "Extracted injected Cobalt Strike beacon configuration with C2 domain 'update.global-cloud-sync.org'"
        ],
        logs: [
          "[09:13:02] Loading memory profile Windows 11 22H2 x64...",
          "[09:13:04] Running pslist, pstree, and malfind plugin suite...",
          "[09:13:06] ALERT: Injected code detected in svchost.exe at memory offset 0x00007FF7B0A20000",
          "[09:13:08] Dumping decrypted strings: found beacon config & named pipe '\\\\.\\pipe\\msse-492-server'."
        ]
      },
      "agent-3": {
        status: "Completed",
        confidence: "94.8%",
        executionTime: "12.4s",
        summary: "Synthesized end-to-end attack timeline from spearphishing payload execution through persistence and credential dumping.",
        findings: [
          "Initial infection occurred via spearphishing email with malicious attachment 'invoice_march2026.iso'",
          "PowerShell execution observed executing base64 encoded stager (EventID 4104)",
          "Persistence established via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry",
          "Lateral movement staging initiated targeting Domain Controller DC-CORP-01"
        ],
        logs: [
          "[09:15:20] Ingesting causality events from Sysmon and Plaso timeline...",
          "[09:15:24] Correlating Outlook process tree: OUTLOOK.EXE -> 7z.exe -> invoice_doc.iso -> payload.scr",
          "[09:15:31] Validating parent-child PID lineage. Anomaly score: 0.982.",
          "[09:15:40] Synthesizing MITRE ATT&CK kill-chain mapping completed."
        ]
      },
      "agent-4": {
        status: "Completed",
        confidence: "93.2%",
        executionTime: "5.2s",
        summary: "Evaluated Kerberos ticket requests and Event ID 4624 logins. Identified lateral authentication attempt toward DC-CORP-01.",
        findings: [
          "Suspicious Kerberos Ticket Granting Service (TGS) request for krbtgt account",
          "SMB pipe '\\\\.\\pipe\\msse-492-server' probed across local subnet /24",
          "Zero secondary hosts breached prior to host quarantine"
        ],
        logs: [
          "[09:16:10] Ingesting Windows Security Event Logs 4624, 4672, 4769...",
          "[09:16:13] Mapping BloodHound shortest attack paths to Active Directory Tier 0...",
          "[09:16:15] Lateral pivoting contained to origin host DESKTOP-WK88."
        ]
      },
      "agent-5a": {
        status: "Completed",
        confidence: "97.0%",
        executionTime: "4.8s",
        summary: "Correlated external IP 194.26.29.112 and payload hashes with active APT-29 / Midnight Blizzard threat feeds.",
        findings: [
          "IP 194.26.29.112 attributed to known APT-29 staging infrastructure (AS204957)",
          "Payload SHA-256 hash matched YARA rule 'APT_NOBELIUM_Stager_2026'",
          "JA3 TLS Fingerprint verified matching Cobalt Strike 4.9 malleable C2 profile"
        ],
        logs: [
          "[09:17:02] Querying MISP, VirusTotal, and internal threat feed clusters...",
          "[09:17:04] High-confidence threat actor attribution: APT-29 (Cozy Bear / Midnight Blizzard).",
          "[09:17:06] STIX 2.1 threat intelligence bundle generated."
        ]
      },
      "agent-5b": {
        status: "Completed",
        confidence: "95.5%",
        executionTime: "6.0s",
        summary: "Identified 1.42 GB encrypted archive transmission to foreign C2 over port 443 with TLS beacon interval of 45 seconds.",
        findings: [
          "1.42 GB encrypted payload staged in %TEMP% and exfiltrated via HTTPS POST",
          "Adversary C2 beacon frequency: 45.2s mean interval with 10% jitter",
          "DNS tunneling sub-channel detected emitting base32 encrypted heartbeat telemetry"
        ],
        logs: [
          "[09:17:30] Analyzing Zeek SSL logs and PCAP stream buffers...",
          "[09:17:34] Exfiltration volume calculated: 1,420 MB across 48 discrete POST streams.",
          "[09:17:36] C2 channel breakdown dispatched to Risk Evaluator."
        ]
      },
      "agent-6": {
        status: "Completed",
        confidence: "92.0%",
        executionTime: "4.1s",
        summary: "Computed enterprise Impact Severity Score (ISS: 87/100 - Critical) and verified 95% Chain of Custody integrity.",
        findings: [
          "Calculated Impact Severity Score (ISS): 87/100 (CRITICAL)",
          "Investigator Confidence Score (ICS): 92% (HIGH CERTAINTY)",
          "Evidence Tamper Score (ETS): 95% (VERIFIED INTEGRITY)",
          "Blast radius isolated to 1 host and 2 corporate identities"
        ],
        logs: [
          "[09:18:10] Ingesting telemetry metrics into Bayesian Risk Decision Matrix...",
          "[09:18:12] THREAT LEVEL EVALUATION: CRITICAL SEVERITY (Score 87/100)",
          "[09:18:14] Generating automated containment recommendations and isolation scripts."
        ]
      },
      "agent-7": {
        status: "Completed",
        confidence: "99.0%",
        executionTime: "8.5s",
        summary: "Synthesized comprehensive multi-audience forensic reports: Executive Briefing, Technical FIR, and Customer Assurance Notice.",
        findings: [
          "Generated Executive Incident Briefing (C-Suite / Board of Directors)",
          "Compiled Detailed Technical Examination & Chain of Custody (Law Enforcement ready)",
          "Produced Customer Security Notice with zero data exposure assurance",
          "Created Tamper-Evident SHA-256 Audit Log chain"
        ],
        logs: [
          "[09:19:00] Ingesting all agent claims, MITRE techniques, and causal graphs...",
          "[09:19:05] Multi-audience report synthesis complete. STIX 2.1 bundle signed.",
          "[09:19:08] Human review verification docket ready for Senior Examiner signoff."
        ]
      }
    },

    // Findings & MITRE Mapping
    findings: {
      attackSummary: {
        initialAccess: {
          title: "Initial Access",
          value: "Spearphishing Email",
          detail: "Targeted email received at 09:05 UTC containing ISO image attachment 'invoice_march2026.iso' with weaponized shortcut.",
          severity: "Critical",
          icon: "mail"
        },
        persistence: {
          title: "Persistence",
          value: "Registry Run Key",
          detail: "Created registry value 'WindowsUpdateHelper' in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing to VBS launcher.",
          severity: "High",
          icon: "shield"
        },
        credentialTheft: {
          title: "Credential Theft",
          value: "Detected (LSASS Dump)",
          detail: "MiniDumpWriteDump API invoked against lsass.exe process by svchost hollowed injection. Kerberos tickets harvested.",
          severity: "Critical",
          icon: "key"
        },
        dataExfiltration: {
          title: "Data Exfiltration",
          value: "Detected (C2 Exfil)",
          detail: "1.42 GB encrypted archive staged in %TEMP% and exfiltrated to external IP 194.26.29.112 over encrypted HTTPS beacon.",
          severity: "Critical",
          icon: "upload-cloud"
        }
      },
      mitreCards: [
        {
          id: "T1566.001",
          technique: "T1566",
          name: "Phishing: Spearphishing Attachment",
          tactic: "Initial Access",
          confidence: "High (98%)",
          evidence: "EVTX EventID 4688, Outlook Mail Item #892",
          description: "Malicious ISO containing shortcut stager delivered to user 'jdoe@acme.corp'."
        },
        {
          id: "T1059.001",
          technique: "T1059",
          name: "Command and Scripting: PowerShell",
          tactic: "Execution",
          confidence: "High (96%)",
          evidence: "ScriptBlockLog EventID 4104, Sysmon EventID 1",
          description: "Obfuscated base64 PowerShell command executed with '-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass'."
        },
        {
          id: "T1547.001",
          technique: "T1547",
          name: "Boot/Logon Autostart: Registry Run Keys",
          tactic: "Persistence",
          confidence: "High (99%)",
          evidence: "Sysmon EventID 13, NTUSER.DAT Registry Hive",
          description: "Persistence configured under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper."
        },
        {
          id: "T1003.001",
          technique: "T1003",
          name: "OS Credential Dumping: LSASS Memory",
          tactic: "Credential Access",
          confidence: "Verified (95%)",
          evidence: "Process Access EventID 10, Memory VAD Scan",
          description: "Read access requested to lsass.exe process memory to extract plaintext NTLM hashes and Kerberos tickets."
        },
        {
          id: "T1071.001",
          technique: "T1071",
          name: "Application Layer Protocol: Web Protocols",
          tactic: "Command and Control",
          confidence: "High (94%)",
          evidence: "PCAP Flow #4102, Zeek SSL Log",
          description: "Periodic beaconing to 194.26.29.112:443 masquerading as legitimate Microsoft Cloud telemetry traffic."
        },
        {
          id: "T1048.003",
          technique: "T1048",
          name: "Exfiltration Over Alternative Protocol",
          tactic: "Exfiltration",
          confidence: "High (91%)",
          evidence: "NetFlow Telemetry, Firewall Egress Audit",
          description: "Staged data chunking and exfiltration via HTTPS POST requests with custom base64 headers."
        }
      ],
      timeline: [
        { time: "09:05:12 UTC", phase: "Initial Access", title: "Email Opened", description: "User opened email 'URGENT: Outstanding Vendor Invoice' from spoofed external domain 'billing@trusted-vendor-portal.com'.", severity: "medium", source: "Outlook MAPI Log" },
        { time: "09:06:04 UTC", phase: "Execution", title: "Payload Downloaded & Mounted", description: "Attachment 'invoice_march2026.iso' mounted as virtual drive E:. Shortcut 'invoice_details.pdf.lnk' clicked.", severity: "high", source: "Sysmon EventID 1" },
        { time: "09:07:31 UTC", phase: "Execution", title: "PowerShell Executed", description: "PowerShell spawned hidden stager to download secondary payload 'svchost_updater.dll' into AppData\\Local\\Temp.", severity: "critical", source: "EventID 4104" },
        { time: "09:08:45 UTC", phase: "Persistence", title: "Registry Modified", description: "Persistence key 'WindowsUpdateHelper' created in HKCU Run registry path.", severity: "high", source: "Sysmon EventID 13" },
        { time: "09:11:10 UTC", phase: "Credential Access", title: "LSASS Process Injection & Dumping", description: "Code hollowed into svchost.exe (PID 4892) requested PROCESS_VM_READ permissions on lsass.exe.", severity: "critical", source: "Volatility VAD Tree" },
        { time: "09:15:22 UTC", phase: "Command & Control", title: "C2 Communication & Beaconing", description: "Initial encrypted TLS beacon established with foreign IP 194.26.29.112:443. Keepalive interval set to 45 seconds.", severity: "critical", source: "Zeek Flow PCAP" }
      ]
    },

    // Knowledge Graph Data
    graphData: {
      nodes: [
        { id: "user_1", label: "jdoe@acme.corp", type: "user", role: "Victim User (Senior Financial Analyst)", color: "#38bdf8", x: 100, y: 180 },
        { id: "email_1", label: "invoice_march2026.eml", type: "email", role: "Spearphishing Email (DKIM Failed)", color: "#fbbf24", x: 260, y: 180 },
        { id: "file_iso", label: "invoice_march2026.iso", type: "file", role: "Malicious Container Image", color: "#c084fc", x: 420, y: 130 },
        { id: "proc_pwsh", label: "powershell.exe (PID 4892)", type: "process", role: "Obfuscated Script Execution", color: "#f43f5e", x: 580, y: 180 },
        { id: "reg_run", label: "HKCU Run: WinUpdate", type: "registry", role: "Persistence Artifact", color: "#fb923c", x: 440, y: 280 },
        { id: "proc_lsass", label: "lsass.exe (PID 672)", type: "process", role: "Target Credential Store", color: "#f43f5e", x: 740, y: 120 },
        { id: "file_dump", label: "lsass_dump.dmp (18MB)", type: "file", role: "Harvested Credential File", color: "#c084fc", x: 890, y: 120 },
        { id: "ip_c2", label: "194.26.29.112:443", type: "ip", role: "Attacker C2 Infrastructure (Frankfurt)", color: "#00f0ff", x: 740, y: 260 },
        { id: "domain_dc", label: "DC-CORP-01", type: "host", role: "Target Domain Controller", color: "#34d399", x: 890, y: 260 }
      ],
      edges: [
        { source: "user_1", target: "email_1", label: "Received & Opened" },
        { source: "email_1", target: "file_iso", label: "Extracted Attachment" },
        { source: "file_iso", target: "proc_pwsh", label: "Executed LNK" },
        { source: "proc_pwsh", target: "reg_run", label: "Created Persistence" },
        { source: "proc_pwsh", target: "proc_lsass", label: "Injected & Read" },
        { source: "proc_lsass", target: "file_dump", label: "Extracted Credentials" },
        { source: "proc_pwsh", target: "ip_c2", label: "TLS Beacon & Exfil" },
        { source: "ip_c2", target: "domain_dc", label: "Targeted Lateral Pivot" }
      ]
    },

    // Risk Assessment Data
    riskAssessment: {
      iss: {
        score: 87,
        max: 100,
        level: "CRITICAL",
        description: "Severe Enterprise Risk. High-privilege credential compromise with active external C2 channel and exfiltration evidence."
      },
      ics: {
        score: 92,
        max: 100,
        level: "HIGH CONFIDENCE",
        description: "92% AI-Investigator correlation certainty derived from 5 independent deterministic engine cross-validations."
      },
      ets: {
        score: 95,
        max: 100,
        level: "VERIFIED INTEGRITY",
        description: "95% Chain of Custody integrity with RFC 3161 hardware timestamping and zero evidence tampering detected."
      },
      blastRadius: {
        compromisedEndpoints: 1,
        compromisedAccounts: 2,
        exfiltratedDataMb: "1,420 MB",
        sensitiveAssetsAtRisk: ["Active Directory Kerberos KDC", "Corporate Financial ERP", "Executive Email Store"]
      }
    },

    // Immediate Actions
    immediateActions: [
      {
        id: "act-1",
        title: "Force Enterprise Password Reset & Revoke MFA",
        detail: "Reset Active Directory credentials for 'jdoe' and invalidate all existing Kerberos TGT and Azure AD refresh tokens.",
        priority: "Critical",
        status: "Recommended",
        category: "Identity Containment",
        scriptCommand: "Revoke-AzureADUserAllRefreshToken -ObjectId 'a948...'"
      },
      {
        id: "act-2",
        title: "Revoke Active Cloud & OAuth Sessions",
        detail: "Terminate all active M365 and AWS SSO sessions originating from workstation DESKTOP-WK88.",
        priority: "Critical",
        status: "Recommended",
        category: "Session Termination",
        scriptCommand: "aws iam list-access-keys --user-name jdoe | deactivate"
      },
      {
        id: "act-3",
        title: "Block Malicious C2 IP on Perimeter Firewalls",
        detail: "Push automated null-route & Palo Alto / Fortinet block rule for 194.26.29.112 across all enterprise egress gateways.",
        priority: "Critical",
        status: "Recommended",
        category: "Perimeter Network",
        scriptCommand: "Add-FirewallBlockRule -IP '194.26.29.112' -Duration '30d'"
      },
      {
        id: "act-4",
        title: "Isolate Endpoint DESKTOP-WK88 via EDR",
        detail: "Quarantine host from local network while maintaining sensor C2 link for live triage and memory retention.",
        priority: "High",
        status: "Recommended",
        category: "Host Isolation",
        scriptCommand: "Invoke-EDRHostIsolation -HostName 'DESKTOP-WK88'"
      },
      {
        id: "act-5",
        title: "Rotate Compromised Service & API Keys",
        detail: "Rotate internal DB service account and Stripe billing API keys discovered in memory dump.",
        priority: "High",
        status: "Recommended",
        category: "Secret Rotation",
        scriptCommand: "Vault-RotateSecret -Path 'secret/db/finance-prod'"
      },
      {
        id: "act-6",
        title: "Notify Data Protection Officer & Affected Users",
        detail: "Prepare GDPR / CCPA breach notification docket in compliance with 72-hour regulatory disclosure requirements.",
        priority: "Medium",
        status: "Recommended",
        category: "Compliance",
        scriptCommand: "Send-RegulatoryNotice -Template 'GDPR-Art33-Breach'"
      }
    ],

    // Human Review Data
    humanReview: {
      confidenceGate: "92% ICS Gate Passed",
      requiredSignoffs: "Senior Forensic Examiner + Lead Incident Commander",
      currentAnalyst: "Agent J. Vance",
      claims: [
        {
          id: "CLM-01",
          claim: "Credential Theft via LSASS In-Memory Dump",
          evidenceId: "E-203",
          evidenceSource: "Memory VAD & EventID 10",
          verification: "Verified",
          confidence: "98%",
          statusBadge: "verified",
          notes: "Confirmed MiniDump API handle opened against LSASS with PROCESS_VM_READ."
        },
        {
          id: "CLM-02",
          claim: "Ransomware Precursor / Shadow Copy Deletion",
          evidenceId: "E-490",
          evidenceSource: "VSS Admin Log",
          verification: "Unverified",
          confidence: "34%",
          statusBadge: "unverified",
          notes: "No vssadmin.exe execution or shadow copy deletion found in Sysmon logs. Likely false correlation."
        },
        {
          id: "CLM-03",
          claim: "Encrypted C2 Beaconing to 194.26.29.112",
          evidenceId: "E-112",
          evidenceSource: "Zeek SSL Flow PCAP",
          verification: "Verified",
          confidence: "95%",
          statusBadge: "verified",
          notes: "Beacon interval 45s with JA3 fingerprint matching known Cobalt Strike profile."
        },
        {
          id: "CLM-04",
          claim: "Persistence via CurrentVersion\\Run Registry Key",
          evidenceId: "E-145",
          evidenceSource: "NTUSER.DAT Registry",
          verification: "Verified",
          confidence: "99%",
          statusBadge: "verified",
          notes: "Value 'WindowsUpdateHelper' created by PowerShell PID 4892."
        },
        {
          id: "CLM-05",
          claim: "Data Exfiltration of Financial Records Archive",
          evidenceId: "E-308",
          evidenceSource: "Network NetFlow Telemetry",
          verification: "Verified",
          confidence: "92%",
          statusBadge: "verified",
          notes: "1.42 GB HTTPS POST transmission aligned with staging file creation."
        }
      ],
      reviewHistory: [
        { reviewer: "Agent Sarah Chen (Tier 2)", action: "Initial Verification Approved", timestamp: "2026-09-01 09:30 UTC" },
        { reviewer: "AI Confidence Engine", action: "Confidence Gate Check (92%) PASSED", timestamp: "2026-09-01 09:28 UTC" }
      ]
    },

    // Reports Data
    reports: {
      executiveSummary: {
        title: "Executive Forensic Incident Briefing",
        date: "September 1, 2026",
        classification: "CONFIDENTIAL // C-SUITE & BOARD",
        preparedFor: "Board of Directors & Chief Information Security Officer",
        incidentSummary: "On September 1, 2026 at 09:05 UTC, an advanced threat actor initiated a targeted spearphishing attack against an enterprise workstation in the finance department. The threat actor successfully executed malicious script payloads, established persistent registry autostart, harvested local domain credentials via memory injection, and established an encrypted command-and-control connection to an external IP in Germany.",
        impactOverview: "Immediate containment protocols have isolated the single affected endpoint before widespread lateral movement into corporate Active Directory Domain Controllers occurred. A total of 1.42 GB of staged local data was transmitted to the adversary infrastructure.",
        containmentStatus: "CONTAINED & QUARANTINED",
        keyMetrics: [
          { label: "Business Impact Severity", value: "87 / 100 (Critical)" },
          { label: "Systems Compromised", value: "1 Workstation (DESKTOP-WK88)" },
          { label: "Investigation Confidence", value: "92% (High Certainty)" },
          { label: "Time to Triage & Contain", value: "22 Minutes" }
        ],
        recommendations: [
          "Enforce hardware-backed FIDO2 MFA across all financial enterprise accounts.",
          "Implement endpoint application whitelisting and restrict ISO/VHD container auto-mounting.",
          "Conduct targeted password resets for all accounts with cached credentials on the compromised machine."
        ]
      },
      technicalReport: {
        title: "Comprehensive Digital Forensic Examination & FIR Analysis",
        date: "September 1, 2026",
        caseReference: "ARG-101 // APT-29 LSASS Investigation",
        chainOfCustody: {
          hashSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          acquisitionTime: "2026-09-01T09:12:04Z",
          imagingTechnique: "Live Raw Physical Memory Capture (WinPmem 4.0) + NTFS E01 Disk Stream",
          verifierAuthority: "ARGUS Hardware Cryptographic Security Module (HSM-Cluster-04)"
        },
        forensicFindings: [
          {
            section: "1. Vector Analysis & Payload Staging",
            details: "Initial infection delivered via email attachment 'invoice_march2026.iso' containing shortcut file pointing to 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Enc WwBTAHkAcwB0AGUAbQAu...'. The stager extracted secondary payload 'svchost_updater.dll' to '%LOCALAPPDATA%\\Temp'."
          },
          {
            section: "2. Volatility Memory Injection & Process Hollowing",
            details: "Process list analysis (pslist / malfind) identified abnormal memory protection flags PAGE_EXECUTE_READWRITE at base address 0x00007FF7B0A20000 within svchost.exe (PID 4892). Process hollowed to conceal Cobalt Strike beacon payload."
          },
          {
            section: "3. Credential Harvesting Mechanics",
            details: "Windows Security Event ID 4656 and Sysmon Event ID 10 confirm svchost.exe (PID 4892) requested 0x1010 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) access rights to lsass.exe (PID 672), followed by invocation of MiniDumpWriteDump."
          },
          {
            section: "4. Network Telemetry & Command and Control",
            details: "Zeek connection logs indicate outbound TLS 1.3 traffic to destination 194.26.29.112 over port 443 with SNI 'update.global-cloud-sync.org'. Jitter analysis shows beacon pulses occurring at 45.2 second mean intervals with 10% randomization."
          }
        ],
        iocs: [
          { type: "IPv4 Address", indicator: "194.26.29.112", context: "Cobalt Strike C2 Server (AS204957)" },
          { type: "Domain Name", indicator: "update.global-cloud-sync.org", context: "Malicious Dynamic DNS Domain" },
          { type: "SHA-256 File", indicator: "b8f418525b6c59b2d87e07a3c3e53d9e831bb2198086f6634c0349df03d21b92", context: "Stager Script (payload.scr)" },
          { type: "Registry Key", indicator: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper", context: "Persistence Autostart" }
        ]
      },
      customerReport: {
        title: "Client Security Incident Notice & Assurance Summary",
        date: "September 1, 2026",
        classification: "CUSTOMER SAFE // NON-TECHNICAL",
        statement: "We take the security of our customers and partners with the utmost seriousness. On September 1, 2026, our automated AI-driven security monitoring platform (ARGUS) detected and neutralized an unauthorized access attempt on an isolated internal computer.",
        assurancePoints: [
          { title: "No Customer Data Exposed", description: "All customer databases and transactional systems remain completely secure and unaffected. No unauthorized access to customer records occurred." },
          { title: "Immediate Threat Containment", description: "The affected computer was disconnected from our network within minutes of detection, preventing any spread to other systems." },
          { title: "Enhanced Protective Measures", description: "All security safeguards, email filtering heuristics, and access permissions have been fortified across our entire organization." },
          { title: "Zero Service Disruption", description: "All client-facing portals, APIs, and cloud services continue to operate normally with 100% availability." }
        ],
        supportContact: "For any questions or security compliance inquiries, contact our Security Operations Center at security-inquiries@acme.corp."
      }
    },

    // Audit Logs
    auditLogs: [
      { id: "AUD-8921", timestamp: "2026-09-01 09:32:10 UTC", actor: "Analyst J. Vance", action: "Approved Claim CLM-01 (LSASS Credential Theft)", hash: "7c98b2e1...8f40", status: "VERIFIED" },
      { id: "AUD-8920", timestamp: "2026-09-01 09:28:44 UTC", actor: "AI Swarm Agent 3", action: "Generated MITRE ATT&CK Causal Execution Tree", hash: "4a12c8e3...9b21", status: "VERIFIED" },
      { id: "AUD-8919", timestamp: "2026-09-01 09:22:30 UTC", actor: "Deterministic Volatility Engine", action: "Extracted VAD Memory Offset 0x00007FF7B0A20000", hash: "99f381ab...2e09", status: "VERIFIED" },
      { id: "AUD-8918", timestamp: "2026-09-01 09:15:10 UTC", actor: "Plaso Rust Pipeline", action: "Parsed 12,430 Artifacts into Standardized FCR", hash: "1d84f09a...7c12", status: "VERIFIED" },
      { id: "AUD-8917", timestamp: "2026-09-01 09:12:04 UTC", actor: "ARGUS Ingestion Gateway", action: "Evidence Registered: SHA-256 e3b0c442... RFC 3161 Certified", hash: "e3b0c442...b855", status: "VERIFIED" }
    ]
  }
};
