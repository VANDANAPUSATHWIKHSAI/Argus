# ARGUS External Forensic Tool & Dependency Verification List

This document lists all external tools, rule sets, symbol packages, and Python dependencies evaluated by the ARGUS discovery system (`python tools/check_external_forensics_tools.py`).

---

## 1. ALREADY BUNDLED / INSTALLED (No Download Needed)

| Tool / Dependency | Status | Location / Discovery Method | Source Families Served |
|---|---|---|---|
| **Volatility 3** (`vol`, `volatility3`) | READY | Python Package (`volatility3`) + 3,019 ISF Symbol Tables Installed | Memory Dump (#1) |
| **The Sleuth Kit (TSK)** (`fls`, `istat`, `icat`, `mmls`) | READY | Bundled at `argus/tsk/sleuthkit-4.15.0-win32/bin` | Filesystem / Disk Images (#18) |
| **Hindsight / pyhindsight** | READY | Python Package (`pyhindsight`) / System PATH | Browser Chrome/Chromium (#7) |
| **Native Python Standard Parsers** | READY | Built-in Python standard library (`email`, `xml.etree`, `sqlite3`) | Firefox (#8), EML (#9), MSG (#10), Tasks (#21), PowerShell History (#22), WMI (#29), Defender (#30), Firewall (#31), Timeline (#32), Search (#33), Sticky Notes (#35), Notification DB (#36), WER (#37), Windows Update (#38), GPO (#39), VSS (#41), DPAPI (#42) |

---

## 2. REQUIRED TOOLS (Genuinely Missing Executables)

These external CLI tools are not packaged inside the repository and must be installed on the host system or placed in `ARGUS_FORENSICS_TOOLS` directory:

| Tool | Executable Candidate | Required By Source Family | Recommended Download / Repository |
|---|---|---|---|
| **Hayabusa** | `hayabusa.exe` / `hayabusa` | Threat-Hunted EVTX (#5), Sysmon (#40) | [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) |
| **RegRipper 3.0** | `rip.exe` / `rip.pl` | Registry (#6), UserAssist (#23), RecentDocs (#24), BAM/DAM (#26), MUICache (#27), Services (#28), Network Configuration (#34) | [keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) |
| **EvtxECmd** | `EvtxECmd.exe` | Raw EVTX (#4) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **MFTECmd** | `MFTECmd.exe` | MFT (#11), USN Journal (#19) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **PECmd** | `PECmd.exe` | Prefetch (#12) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **LECmd** | `LECmd.exe` | LNK Shortcuts (#13) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **JLECmd** | `JLECmd.exe` | Jump Lists (#14) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **RBCmd** | `RBCmd.exe` | Recycle Bin (#15) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **AmcacheParser** | `AmcacheParser.exe` | Amcache (#16) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **SrumECmd** | `SrumECmd.exe` | SRUM (#17) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **AppCompatCacheParser** | `AppCompatCacheParser.exe` | ShimCache (#20) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **SBECmd** | `SBECmd.exe` | ShellBags (#25) | [Eric Zimmerman Tools](https://ericzimmerman.github.io/) |
| **Zeek** | `zeek.exe` / `zeek` | PCAP Network Traffic (#2) | [Zeek Project](https://zeek.org/) / WSL |
| **Suricata** | `suricata.exe` / `suricata` | Network IDS (#3) | [Suricata Project](https://suricata.io/) / WSL |

---

## 3. REQUIRED PLUGINS / RULES

| Tool | Required Rule / Plugin Set | Location Expected |
|---|---|---|
| **Hayabusa** | Official Sigma & Hayabusa ruleset | `rules/` directory alongside `hayabusa.exe` |
| **RegRipper 3.0** | Perl plugin scripts (`*.pl`) | `plugins/` directory alongside `rip.exe` / `rip.pl` |

---

## 4. REQUIRED SYMBOLS

| Tool | Required Symbol Set | Location Expected |
|---|---|---|
| **Volatility 3** | Windows Intermediate Symbol Files (ISF symbol tables `windows.zip`) | `symbols/windows/` directory in Volatility 3 or `ARGUS_FORENSICS_TOOLS/symbols/windows` |

---

## 5. PYTHON DEPENDENCIES

Installed via `pip install -r requirements-forensics.txt`:

- `volatility3` (Memory Dump parsing)
- `extract-msg` (Outlook MSG email parsing)
- `pyhindsight` (Chrome/Chromium browser parsing)

---

## 6. OPTIONAL / SYSTEM DEPENDENCIES

- **Strawberry Perl** (Required to execute `rip.pl` if using Perl version of RegRipper).
- **WSL / Linux Environment** (Optional alternative environment for Zeek and Suricata).

---

## 7. Actionable Next Steps

1. Download missing Zimmerman CLI binaries from Eric Zimmerman's official tool page.
2. Download Hayabusa binary + `rules/` folder.
3. Download RegRipper 3.0 binary/script + `plugins/` folder.
4. Place tools in PATH or in folder referenced by `ARGUS_FORENSICS_TOOLS`.
5. Run discovery:
   ```powershell
   python tools/check_external_forensics_tools.py
   ```
