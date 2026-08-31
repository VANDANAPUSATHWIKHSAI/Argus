from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# ---------------------------------------------------------------------------
# Discovery Path Resolution (Portable, Priority-Based)
# ---------------------------------------------------------------------------

def get_repo_root() -> Path:
    """Determine repository root dynamically without hardcoded absolute paths."""
    script_dir = Path(__file__).resolve().parent
    if script_dir.name == "tools":
        if script_dir.parent.name == "argus":
            return script_dir.parent.parent
        return script_dir.parent
    return script_dir.parent

def build_search_directories() -> List[Tuple[Path, str]]:
    """
    Build prioritized list of (Path, discovery_method_label).
    Priority:
      1. ARGUS_FORENSICS_TOOLS environment variable / config paths
      2. ARGUS project-local tool directories
      3. System PATH
    """
    search_dirs: List[Tuple[Path, str]] = []
    seen: set = set()

    def add_dir(p: Path, label: str):
        try:
            resolved = p.resolve()
            if resolved.exists() and resolved.is_dir() and str(resolved) not in seen:
                seen.add(str(resolved))
                search_dirs.append((resolved, label))
        except Exception:
            pass

    # Priority 1: Environment variable ARGUS_FORENSICS_TOOLS
    env_custom = os.environ.get("ARGUS_FORENSICS_TOOLS")
    if env_custom:
        custom_p = Path(env_custom)
        add_dir(custom_p, "ARGUS_FORENSICS_TOOLS (Env)")
        if custom_p.exists() and custom_p.is_dir():
            for child in custom_p.iterdir():
                if child.is_dir():
                    add_dir(child, f"ARGUS_FORENSICS_TOOLS/{child.name}")

    # Priority 2: ARGUS project-local directories
    root = get_repo_root()
    local_subdirs = [
        ("argus", "Project-Local (argus/)"),
        ("tools", "Project-Local (tools/)"),
        ("argus/tools", "Project-Local (argus/tools/)"),
        ("bin", "Project-Local (bin/)"),
        ("argus/bin", "Project-Local (argus/bin/)"),
        ("external_tools", "Project-Local (external_tools/)"),
        ("third_party", "Project-Local (third_party/)"),
        ("vendor", "Project-Local (vendor/)"),
        ("forensic_tools", "Project-Local (forensic_tools/)"),
    ]

    for rel_path, label in local_subdirs:
        sub_p = root / rel_path
        add_dir(sub_p, label)
        if sub_p.exists() and sub_p.is_dir():
            for root_dir, dirs, _ in os.walk(sub_p):
                depth = len(Path(root_dir).relative_to(sub_p).parts)
                if depth <= 4:
                    add_dir(Path(root_dir), f"{label}/{Path(root_dir).relative_to(sub_p)}")
                else:
                    dirs.clear()

    # Search for bundled Sleuthkit / TSK under argus/tsk/ or tsk/
    for tsk_parent in [root / "argus" / "tsk", root / "tsk"]:
        if tsk_parent.exists() and tsk_parent.is_dir():
            for child in tsk_parent.iterdir():
                if child.is_dir():
                    bin_dir = child / "bin" if (child / "bin").exists() else child
                    add_dir(bin_dir, f"Project-Local Bundled TSK ({child.name})")

    # Priority 3: System PATH
    path_env = os.environ.get("PATH", "")
    for p_str in path_env.split(os.pathsep):
        if p_str.strip():
            add_dir(Path(p_str.strip()), "System PATH")

    return search_dirs

SEARCH_DIRS = build_search_directories()

def find_file(candidates: List[str]) -> Tuple[Optional[Path], Optional[str]]:
    """Search for candidate filenames in prioritized search directories."""
    for candidate in candidates:
        for s_dir, label in SEARCH_DIRS:
            target = s_dir / candidate
            if target.is_file() and os.access(target, os.X_OK | os.R_OK):
                return target, label
            # On Windows, try adding .exe / .bat / .cmd if missing extension
            if sys.platform == "win32" and not candidate.lower().endswith((".exe", ".bat", ".cmd", ".py", ".pl")):
                for ext in [".exe", ".bat", ".cmd", ".py", ".pl"]:
                    target_ext = s_dir / f"{candidate}{ext}"
                    if target_ext.is_file():
                        return target_ext, label
    return None, None

def check_python_package(pkg_name: str) -> bool:
    """Check if a Python package is importable."""
    try:
        spec = importlib.util.find_spec(pkg_name)
        return spec is not None
    except Exception:
        return False

def detect_version(path: Path) -> str:
    """Safely obtain version string from CLI binary using argument arrays."""
    if not path or not path.exists():
        return "VERSION UNKNOWN"
    
    cmd = [str(path)]
    if path.suffix.lower() == ".py":
        cmd = [sys.executable, str(path)]
    elif path.suffix.lower() == ".pl":
        perl_path, _ = find_file(["perl.exe", "perl"])
        perl_bin = str(perl_path) if perl_path else shutil.which("perl")
        if perl_bin:
            cmd = [perl_bin, str(path)]
        else:
            return "VERSION UNKNOWN (Perl required)"

    # Prioritize -V / --version
    for arg in ["-V", "--version", "-v", "version", "/?"]:
        try:
            r = subprocess.run(
                [*cmd, arg],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = (r.stdout + "\n" + r.stderr).strip().splitlines()
            for line in output:
                line_str = line.strip()
                line_lower = line_str.lower()
                if (
                    line_str 
                    and not line_lower.startswith("usage:")
                    and not line_lower.startswith("error")
                    and "invalid" not in line_lower
                    and "unrecognized" not in line_lower
                    and "unknown" not in line_lower
                ):
                    return line_str[:120]
        except Exception:
            pass
    return "VERSION UNKNOWN"

# ---------------------------------------------------------------------------
# Component Checker Functions
# ---------------------------------------------------------------------------

def check_volatility3() -> Dict[str, Any]:
    exe_path, method = find_file(["vol.py", "vol", "volatility3.exe", "volatility3"])
    pkg_found = check_python_package("volatility3")
    
    executable_status = "FOUND" if (exe_path or pkg_found) else "MISSING"
    discovery_method = method or ("Python Package (volatility3)" if pkg_found else "None")
    
    ver = "VERSION UNKNOWN"
    if pkg_found:
        try:
            import volatility3
            ver = getattr(volatility3, "__version__", "FOUND (volatility3)")
        except Exception:
            ver = "FOUND (volatility3)"
    elif exe_path:
        ver = detect_version(exe_path)

    # Check Windows plugins
    plugins_found = False
    req_plugins = [
        "pslist", "pstree", "psscan", "cmdline", "cmdscan", "netscan", "malfind", "dlllist"
    ]
    
    if pkg_found:
        try:
            import volatility3.plugins.windows as win_plugins
            plugins_found = True
        except Exception:
            pass
            
    if not plugins_found and exe_path:
        # Check plugin directory alongside vol binary
        vol_dir = exe_path.parent
        if (vol_dir / "volatility3" / "framework" / "plugins" / "windows").exists():
            plugins_found = True

    # Check Symbols (ISF JSON symbol tables for Windows)
    symbols_found = False
    for s_dir, _ in SEARCH_DIRS:
        sym_dir = s_dir / "symbols" / "windows"
        if sym_dir.exists() and sym_dir.is_dir() and any(sym_dir.glob("*.json")):
            symbols_found = True
            break
            
    if not symbols_found and pkg_found:
        try:
            import volatility3.symbols as sym_mod
            sym_path = Path(sym_mod.__file__).parent / "windows"
            if sym_path.exists() and any(sym_path.rglob("*.json*")):
                symbols_found = True
        except Exception:
            pass

    if plugins_found and symbols_found:
        prs_status = "FOUND"
    elif plugins_found:
        prs_status = "PLUGINS_FOUND, SYMBOLS_MISSING"
    elif symbols_found:
        prs_status = "SYMBOLS_FOUND, PLUGINS_MISSING"
    else:
        prs_status = "MISSING"

    if executable_status == "FOUND" and plugins_found and symbols_found:
        status = "READY"
    elif executable_status == "FOUND":
        status = "INCOMPLETE"
    else:
        status = "MISSING"

    return {
        "tool": "Volatility 3",
        "executable": executable_status,
        "dependencies": "FOUND" if pkg_found else "MISSING",
        "plugins_rules_symbols": prs_status,
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else None,
        "why_needed": "Processes raw memory dumps (.raw, .vmem, .dmp) for processes, network, DLLs, and malware.",
        "used_by": "MemoryParser (Source #1)",
        "download_item": "Volatility 3 source/package and Volatility 3 Windows Symbol Pack (windows.zip)"
    }

def check_hayabusa() -> Dict[str, Any]:
    exe_path, method = find_file(["hayabusa.exe", "hayabusa", "hayabusa-4.0.0-win-x64.exe"])
    executable_status = "FOUND" if exe_path else "MISSING"
    discovery_method = method or "None"
    
    ver = detect_version(exe_path) if exe_path else "VERSION UNKNOWN"

    # Check required rules/config
    rules_found = False
    if exe_path:
        exe_dir = exe_path.parent
        if (exe_dir / "rules").exists() or (exe_dir / "config").exists():
            rules_found = True
    
    if not rules_found:
        for s_dir, _ in SEARCH_DIRS:
            if (s_dir / "rules").exists() or (s_dir / "hayabusa_rules").exists():
                rules_found = True
                break

    plugins_rules_symbols = "FOUND" if rules_found else "MISSING"
    
    if executable_status == "FOUND" and rules_found:
        status = "READY"
    elif executable_status == "FOUND":
        status = "INCOMPLETE"
    else:
        status = "MISSING"

    return {
        "tool": "Hayabusa",
        "executable": executable_status,
        "dependencies": "N/A",
        "plugins_rules_symbols": plugins_rules_symbols,
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else None,
        "why_needed": "Threat-hunts Windows EVTX logs and Sysmon operational logs against Sigma rules.",
        "used_by": "EvtxParser (Source #5, #40)",
        "download_item": "Hayabusa binary release and official Hayabusa ruleset (rules/ directory)"
    }

def check_regripper() -> Dict[str, Any]:
    exe_path, method = find_file(["rip.exe", "rip.pl", "rip"])
    executable_status = "FOUND" if exe_path else "MISSING"
    discovery_method = method or "None"
    
    ver = detect_version(exe_path) if exe_path else "VERSION UNKNOWN"

    # Check plugins directory containing .pl scripts
    plugins_found = False
    if exe_path:
        plug_dir = exe_path.parent / "plugins"
        if plug_dir.exists() and plug_dir.is_dir() and any(plug_dir.glob("*.pl")):
            plugins_found = True
            
    if not plugins_found:
        for s_dir, _ in SEARCH_DIRS:
            plug_dir = s_dir / "plugins"
            if plug_dir.exists() and plug_dir.is_dir() and any(plug_dir.glob("*.pl")):
                plugins_found = True
                break

    perl_path, _ = find_file(["perl.exe", "perl"])
    perl_installed = (perl_path is not None) or (shutil.which("perl") is not None)
    deps_status = "Perl FOUND" if perl_installed else "Perl MISSING"
    plugins_rules_symbols = "FOUND" if plugins_found else "MISSING"

    if executable_status == "FOUND" and plugins_found and perl_installed:
        status = "READY"
    elif executable_status == "FOUND":
        status = "INCOMPLETE"
    else:
        status = "MISSING"

    return {
        "tool": "RegRipper 3.0",
        "executable": executable_status,
        "dependencies": deps_status,
        "plugins_rules_symbols": plugins_rules_symbols,
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else None,
        "why_needed": "Parses Registry hives for UserAssist, RecentDocs, BAM/DAM, Services, MUICache, Network Config.",
        "used_by": "RegistryParser (Source #6, #23, #24, #26, #27, #28, #34)",
        "download_item": "RegRipper 3.0 (rip.exe / rip.pl + full plugins/ directory) and Strawberry Perl"
    }

def check_zimmerman_tool(tool_name: str, exe_candidates: List[str], source_num: str, description: str) -> Dict[str, Any]:
    exe_path, method = find_file(exe_candidates)
    executable_status = "FOUND" if exe_path else "MISSING"
    discovery_method = method or "None"
    ver = detect_version(exe_path) if exe_path else "VERSION UNKNOWN"
    status = "READY" if executable_status == "FOUND" else "MISSING"

    return {
        "tool": tool_name,
        "executable": executable_status,
        "dependencies": "N/A",
        "plugins_rules_symbols": "N/A",
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else None,
        "why_needed": description,
        "used_by": f"Eric Zimmerman Tools ({source_num})",
        "download_item": f"{tool_name} binary ({exe_candidates[0]}) from Eric Zimmerman's tools"
    }

def check_wsl_binary(cmd_name: str) -> Tuple[bool, str, str]:
    """Check if command is available via batch wrapper or WSL."""
    bat_exe, bat_label = find_file([f"{cmd_name}.bat", f"{cmd_name}.cmd"])
    if bat_exe:
        return True, f"FOUND ({cmd_name}.bat wrapper)", f"Project-Local ({bat_label})"
    if sys.platform == "win32":
        try:
            r = subprocess.run(["wsl.exe", "sh", "-c", f"which {cmd_name}"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                wsl_path = r.stdout.strip()
                ver_r = subprocess.run(["wsl.exe", "sh", "-c", f"{cmd_name} --version || {cmd_name} -V"], capture_output=True, text=True, timeout=5)
                out_lines = [l.strip() for l in (ver_r.stdout + "\n" + ver_r.stderr).splitlines() if l.strip()]
                ver_str = out_lines[0] if out_lines else "FOUND (WSL)"
                return True, ver_str, f"WSL ({wsl_path})"
        except Exception:
            pass
    return False, "VERSION UNKNOWN", ""

def check_zeek() -> Dict[str, Any]:
    exe_path, method = find_file(["zeek.exe", "zeek"])
    wsl_found, wsl_ver, wsl_method = (False, "", "")
    if not exe_path:
        wsl_found, wsl_ver, wsl_method = check_wsl_binary("zeek")

    executable_status = "FOUND" if (exe_path or wsl_found) else "MISSING"
    discovery_method = method or (wsl_method if wsl_found else "None")
    ver = detect_version(exe_path) if exe_path else (wsl_ver if wsl_found else "VERSION UNKNOWN")
    status = "READY" if executable_status == "FOUND" else "MISSING"

    return {
        "tool": "Zeek",
        "executable": executable_status,
        "dependencies": "N/A",
        "plugins_rules_symbols": "N/A",
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else (wsl_method if wsl_found else None),
        "why_needed": "Parses PCAP network traffic into connection, DNS, HTTP, and SSL logs.",
        "used_by": "PcapParser (Source #2)",
        "download_item": "Zeek network security monitor binary"
    }

def check_suricata() -> Dict[str, Any]:
    exe_path, method = find_file(["suricata.exe", "suricata"])
    wsl_found, wsl_ver, wsl_method = (False, "", "")
    if not exe_path:
        wsl_found, wsl_ver, wsl_method = check_wsl_binary("suricata")

    executable_status = "FOUND" if (exe_path or wsl_found) else "MISSING"
    discovery_method = method or (wsl_method if wsl_found else "None")
    ver = detect_version(exe_path) if exe_path else (wsl_ver if wsl_found else "VERSION UNKNOWN")
    status = "READY" if executable_status == "FOUND" else "MISSING"

    return {
        "tool": "Suricata",
        "executable": executable_status,
        "dependencies": "N/A",
        "plugins_rules_symbols": "N/A",
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else (wsl_method if wsl_found else None),
        "why_needed": "Parses network IDS alert logs (EVE JSON / PCAP).",
        "used_by": "PcapParser (Source #3)",
        "download_item": "Suricata IDS binary engine"
    }

def check_hindsight() -> Dict[str, Any]:
    exe_path, method = find_file(["hindsight.py", "hindsight", "hindsight.exe"])
    pkg_found = check_python_package("pyhindsight") or check_python_package("hindsight")
    
    executable_status = "FOUND" if (exe_path or pkg_found) else "MISSING"
    discovery_method = method or ("Python Package (pyhindsight)" if pkg_found else "None")
    
    ver = "VERSION UNKNOWN"
    if pkg_found:
        try:
            import pyhindsight
            ver = getattr(pyhindsight, "__version__", "FOUND (pyhindsight)")
        except Exception:
            ver = "FOUND (pyhindsight)"
    elif exe_path:
        ver = detect_version(exe_path)

    status = "READY" if executable_status == "FOUND" else "MISSING"

    return {
        "tool": "Hindsight",
        "executable": executable_status,
        "dependencies": "FOUND" if pkg_found else "MISSING",
        "plugins_rules_symbols": "N/A",
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(exe_path) if exe_path else None,
        "why_needed": "Parses Chrome/Chromium web browser history, cookies, and downloads.",
        "used_by": "BrowserParser (Source #7)",
        "download_item": "pip install pyhindsight or Hindsight executable"
    }

def check_tsk() -> Dict[str, Any]:
    root = get_repo_root()
    bundled_found = False
    bundled_path = None
    
    # Check bundled Sleuth Kit path first
    for tsk_parent in [root / "argus" / "tsk", root / "tsk"]:
        if tsk_parent.exists() and tsk_parent.is_dir():
            for child in tsk_parent.iterdir():
                if child.is_dir():
                    bin_dir = child / "bin" if (child / "bin").exists() else child
                    fls_bin = bin_dir / ("fls.exe" if sys.platform == "win32" else "fls")
                    if fls_bin.exists():
                        bundled_found = True
                        bundled_path = bin_dir
                        break

    exe_path, method = find_file(["fls.exe", "fls"])
    
    if bundled_found and bundled_path:
        executable_status = "FOUND"
        discovery_method = f"Bundled Project TSK ({bundled_path.parent.name})"
        target_bin = bundled_path / ("fls.exe" if sys.platform == "win32" else "fls")
        ver = detect_version(target_bin)
        status = "READY"
    elif exe_path:
        executable_status = "FOUND"
        discovery_method = method or "System PATH"
        ver = detect_version(exe_path)
        status = "READY"
    else:
        executable_status = "MISSING"
        discovery_method = "None"
        ver = "VERSION UNKNOWN"
        status = "MISSING"

    return {
        "tool": "The Sleuth Kit (TSK)",
        "executable": executable_status,
        "dependencies": "FOUND (Bundled)" if bundled_found else ("FOUND" if exe_path else "MISSING"),
        "plugins_rules_symbols": "N/A",
        "version": ver,
        "discovery_method": discovery_method,
        "status": status,
        "path": str(bundled_path or exe_path) if (bundled_path or exe_path) else None,
        "why_needed": "Parses disk image filesystems (E01, RAW, DD) using fls, istat, icat, mmls.",
        "used_by": "FilesystemParser (Source #18)",
        "download_item": "Bundled distribution already included in argus/tsk/ sleuthkit"
    }

# ---------------------------------------------------------------------------
# Main Health Checker Runner
# ---------------------------------------------------------------------------

def run_health_check() -> List[Dict[str, Any]]:
    zimmerman_tools = [
        ("EvtxECmd", ["EvtxECmd.exe", "EvtxECmd"], "Source #4", "Parses raw EVTX event log files into JSON."),
        ("MFTECmd", ["MFTECmd.exe", "MFTECmd"], "Source #11, #19", "Parses $MFT and USN Journal files."),
        ("PECmd", ["PECmd.exe", "PECmd"], "Source #12", "Parses Windows Prefetch (.pf) files."),
        ("LECmd", ["LECmd.exe", "LECmd"], "Source #13", "Parses Windows LNK shortcut files."),
        ("JLECmd", ["JLECmd.exe", "JLECmd"], "Source #14", "Parses Automatic and Custom Jump Lists."),
        ("RBCmd", ["RBCmd.exe", "RBCmd"], "Source #15", "Parses Windows Recycle Bin $I files."),
        ("AmcacheParser", ["AmcacheParser.exe", "AmcacheParser"], "Source #16", "Parses Amcache.hve registry hive."),
        ("SrumECmd", ["SrumECmd.exe", "SrumECmd"], "Source #17", "Parses SRUDB.dat System Resource Usage Monitor database."),
        ("AppCompatCacheParser", ["AppCompatCacheParser.exe", "AppCompatCacheParser"], "Source #20", "Parses ShimCache / AppCompatCache."),
        ("SBECmd", ["SBECmd.exe", "SBECmd"], "Source #25", "Parses Windows ShellBags."),
    ]

    results: List[Dict[str, Any]] = []
    
    results.append(check_volatility3())
    results.append(check_hayabusa())
    results.append(check_regripper())
    
    for name, candidates, src_num, desc in zimmerman_tools:
        results.append(check_zimmerman_tool(name, candidates, src_num, desc))

    results.append(check_zeek())
    results.append(check_suricata())
    results.append(check_hindsight())
    results.append(check_tsk())

    return results

def print_health_report(results: List[Dict[str, Any]]):
    print("=" * 115)
    print("                      ARGUS EXTERNAL FORENSICS HEALTH CHECK")
    print("=" * 115)
    print(f"{'Tool':<22} {'Executable':<12} {'Dependencies':<14} {'Plugins/Rules/Symbols':<24} {'Version':<18} {'Status':<12}")
    print("-" * 115)

    ready_count = 0
    incomplete_count = 0
    missing_count = 0

    for r in results:
        t_name = r["tool"][:21]
        exe = r["executable"][:11]
        deps = r["dependencies"][:13]
        prs = r["plugins_rules_symbols"][:23]
        ver = r["version"][:17]
        st = r["status"]

        if st == "READY":
            ready_count += 1
        elif st == "INCOMPLETE":
            incomplete_count += 1
        else:
            missing_count += 1

        print(f"{t_name:<22} {exe:<12} {deps:<14} {prs:<24} {ver:<18} {st:<12}")

    print("=" * 115)
    print(f"Summary Statistics:")
    print(f"  Total External Tools Checked : {len(results)}")
    print(f"  Ready for Live Verification : {ready_count}")
    print(f"  Incomplete (Rules/Symbols Missing) : {incomplete_count}")
    print(f"  Missing Executables         : {missing_count}")
    print("=" * 115)

    # Detailed DOWNLOAD EXTERNALLY Section
    missing_tools = [r for r in results if r["status"] in ("MISSING", "INCOMPLETE")]
    print("\nDOWNLOAD EXTERNALLY (Genuinely Missing Requirements):")
    print("-" * 115)
    if not missing_tools:
        print("  None! All external forensic tools, dependencies, and rules are installed and ready.")
    else:
        for r in missing_tools:
            print(f"  - Tool       : {r['tool']} (Status: {r['status']})")
            print(f"    Download   : {r['download_item']}")
            print(f"    Why Needed : {r['why_needed']}")
            print(f"    Used By    : {r['used_by']}")
            print()

    # Detailed ALREADY AVAILABLE Section
    ready_tools = [r for r in results if r["status"] == "READY"]
    print("ALREADY AVAILABLE (Present and Configured):")
    print("-" * 115)
    for r in ready_tools:
        print(f"  [READY] {r['tool']:<22} | Method: {r['discovery_method']:<35} | Path: {r['path']}")

    print("=" * 115)
    print("NEXT STEP:")
    if missing_tools:
        print("  1. Download and install the external tools listed under 'DOWNLOAD EXTERNALLY' above.")
        print("  2. Place executables in system PATH or set environment variable ARGUS_FORENSICS_TOOLS.")
        print("  3. Re-run this check (python tools/check_external_forensics_tools.py).")
        print("  4. Execute real forensic sample evidence through the ARGUS parser pipeline.")
    else:
        print("  Environment is 100% prepared for live forensic evidence verification!")
    print("=" * 115)

def main():
    results = run_health_check()
    print_health_report(results)
    has_missing = any(r["status"] != "READY" for r in results)
    return 1 if has_missing else 0

if __name__ == "__main__":
    sys.exit(main())
