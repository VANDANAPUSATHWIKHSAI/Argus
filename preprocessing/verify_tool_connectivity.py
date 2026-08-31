import os
import sys
import subprocess
import shutil
import re
from pathlib import Path
from typing import Dict, Any, Optional

# Ensure the script runs with the project root (argus directory) on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from preprocessing.parsers.evtx_parser import EvtxParser, HayabusaExecutionError, HayabusaNotFoundError
from preprocessing.parsers.pcap_parser import PcapParser, ZeekExecutionError, ZeekNotFoundError, SuricataExecutionError, SuricataNotFoundError
from preprocessing.parsers.memory_parser import MemoryParser, VolatilityExecutionError, VolatilityNotFoundError
from preprocessing.parsers.registry_parser import RegistryParser, RegRipperNotFoundError, RegRipperExecutionError
from preprocessing.parsers.browser_parser import BrowserParser, HindsightExecutionError, HindsightNotFoundError
from preprocessing.parsers.filesystem_parser import FilesystemParser, TSKExecutionError, TSKNotFoundError

def run_cmd(cmd, shell=False, timeout=20):
    try:
        res = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            shell=shell, 
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        return res.returncode, res.stdout or "", res.stderr or "", None
    except Exception as e:
        return None, "", "", e

def main():
    print("==========================================================")
    print("Argus Tool Connectivity & Connectivity Pre-Deployment Check")
    print("==========================================================\n")

    results = {}
    
    # ----------------------------------------------------
    # 1. Hayabusa Check
    # ----------------------------------------------------
    print("Checking Hayabusa...")
    rc, stdout, stderr, exc = run_cmd(["hayabusa", "--version"])
    hayabusa_direct = "FOUND" if exc is None else "NOT FOUND"
    if exc:
        hayabusa_direct = f"NOT FOUND ({type(exc).__name__})"
    elif rc != 0:
        hayabusa_direct = f"FOUND (exit code {rc})"
        
    s_rc, s_out, s_err, s_exc = run_cmd("hayabusa", shell=True)
    hayabusa_shell = "yes" if s_exc is None and (s_rc == 0 or "Yamato Security" in (s_out + s_err)) else "no"
    
    parser_evtx = EvtxParser()
    try:
        parser_evtx._run_hayabusa(Path("dummy_nonexistent.evtx"), Path("dummy_out.jsonl"))
        hayabusa_parser = "yes"
    except HayabusaExecutionError:
        hayabusa_parser = "yes"
    except HayabusaNotFoundError:
        hayabusa_parser = "no"
    except Exception as e:
        hayabusa_parser = f"no ({type(e).__name__})"
        
    version_hayabusa = "Unknown"
    _, h_out, h_err, _ = run_cmd(["hayabusa"])
    banner = (h_out or "") + (h_err or "")
    m = re.search(r"Hayabusa v([\d.]+)", banner)
    if m:
        version_hayabusa = m.group(1)
        
    results["Hayabusa"] = {
        "direct": hayabusa_direct,
        "shell": hayabusa_shell,
        "parser": hayabusa_parser,
        "version": version_hayabusa,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 2. Zeek Check
    # ----------------------------------------------------
    print("Checking Zeek...")
    rc, stdout, stderr, exc = run_cmd(["zeek", "--version"])
    zeek_direct = "FOUND" if exc is None else "NOT FOUND"
    if exc:
        zeek_direct = f"NOT FOUND ({type(exc).__name__})"
    elif rc != 0:
        zeek_direct = f"FOUND BUT ERRORED (exit code {rc})"
        
    s_rc, s_out, s_err, s_exc = run_cmd("zeek --version", shell=True)
    zeek_shell = "yes" if s_exc is None and ("zeek version" in (s_out + s_err) or "problem with trace file" in (s_out + s_err)) else "no"
    
    parser_pcap = PcapParser()
    try:
        parser_pcap._run_zeek(Path("dummy_nonexistent.pcap"), Path("."))
        zeek_parser = "yes"
    except ZeekExecutionError:
        zeek_parser = "yes"
    except ZeekNotFoundError:
        zeek_parser = "no"
    except Exception as e:
        zeek_parser = f"no ({type(e).__name__})"
        
    version_zeek = "Unknown"
    _, wsl_out, wsl_err, _ = run_cmd(["wsl", "/opt/zeek/bin/zeek", "--version"])
    m = re.search(r"version\s+([\d.]+)", (wsl_out or "") + (wsl_err or ""))
    if m:
        version_zeek = m.group(1)
        
    results["Zeek"] = {
        "direct": zeek_direct,
        "shell": zeek_shell,
        "parser": zeek_parser,
        "version": version_zeek,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 3. Suricata Check
    # ----------------------------------------------------
    print("Checking Suricata...")
    rc, stdout, stderr, exc = run_cmd(["suricata", "--version"])
    suricata_direct = "FOUND" if exc is None else "NOT FOUND"
    if exc:
        suricata_direct = f"NOT FOUND ({type(exc).__name__})"
    elif rc != 0:
        suricata_direct = f"FOUND BUT ERRORED (exit code {rc})"
        
    s_rc, s_out, s_err, s_exc = run_cmd("suricata --version", shell=True)
    suricata_shell = "yes" if s_exc is None and ("Suricata version" in (s_out + s_err) or "USAGE: suricata" in (s_out + s_err)) else "no"
    
    try:
        parser_pcap._run_suricata(Path("dummy_nonexistent.pcap"), Path("."))
        suricata_parser = "yes"
    except SuricataExecutionError:
        suricata_parser = "yes"
    except SuricataNotFoundError:
        suricata_parser = "no"
    except Exception as e:
        suricata_parser = f"no ({type(e).__name__})"
        
    version_suricata = "Unknown"
    _, wsl_out, wsl_err, _ = run_cmd(["wsl", "suricata", "-V"])
    m = re.search(r"version\s+([\d.]+)", (wsl_out or "") + (wsl_err or ""))
    if m:
        version_suricata = m.group(1)
        
    results["Suricata"] = {
        "direct": suricata_direct,
        "shell": suricata_shell,
        "parser": suricata_parser,
        "version": version_suricata,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 4. Volatility3 Check
    # ----------------------------------------------------
    print("Checking Volatility3...")
    rc, stdout, stderr, exc = run_cmd(["vol", "--help"])
    vol_direct = "FOUND" if exc is None else "NOT FOUND"
    if exc:
        vol_direct = f"NOT FOUND ({type(exc).__name__})"
    elif rc != 0:
        vol_direct = f"FOUND BUT ERRORED (exit code {rc})"
        
    s_rc, s_out, s_err, s_exc = run_cmd("vol --help", shell=True)
    vol_shell = "yes" if s_exc is None and s_rc == 0 else "no"
    
    parser_mem = MemoryParser()
    try:
        parser_mem._run_vol(Path("dummy_nonexistent.dmp"), "windows.pslist", json_output=True)
        vol_parser = "yes"
    except VolatilityExecutionError:
        vol_parser = "yes"
    except VolatilityNotFoundError:
        vol_parser = "no"
    except Exception as e:
        vol_parser = f"no ({type(e).__name__})"
        
    version_vol = "Unknown"
    try:
        import importlib.metadata
        version_vol = importlib.metadata.version('volatility3')
    except Exception:
        pass
        
    results["Volatility3"] = {
        "direct": vol_direct,
        "shell": vol_shell,
        "parser": vol_parser,
        "version": version_vol,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 5. Perl Check
    # ----------------------------------------------------
    print("Checking Perl...")
    rc, stdout, stderr, exc = run_cmd(["perl", "-v"])
    perl_direct = "FOUND" if exc is None else "NOT FOUND"
    if exc:
        perl_direct = f"NOT FOUND ({type(exc).__name__})"
    elif rc != 0:
        perl_direct = f"FOUND BUT ERRORED (exit code {rc})"
        
    s_rc, s_out, s_err, s_exc = run_cmd("perl -v", shell=True)
    perl_shell = "yes" if s_exc is None and s_rc == 0 else "no"
    
    perl_parser = "N/A"
    
    version_perl = "Unknown"
    _, wsl_out, wsl_err, _ = run_cmd(["wsl", "perl", "-v"])
    m = re.search(r"v(\d+\.\d+\.\d+)", (wsl_out or "") + (wsl_err or ""))
    if m:
        version_perl = m.group(1)
        
    results["Perl"] = {
        "direct": perl_direct,
        "shell": perl_shell,
        "parser": perl_parser,
        "version": version_perl,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 6. RegRipper Check
    # ----------------------------------------------------
    print("Checking RegRipper...")
    rc, stdout, stderr, exc = run_cmd(["rip.pl", "-h"])
    rip_direct = "FOUND" if exc is None else "NOT FOUND"
    if exc:
        rip_direct = f"NOT FOUND ({type(exc).__name__})"
    elif rc != 0:
        rip_direct = f"FOUND BUT ERRORED (exit code {rc})"
        
    s_rc, s_out, s_err, s_exc = run_cmd("rip.pl -h", shell=True)
    rip_shell = "yes" if s_exc is None and s_rc == 0 else "no"
    
    parser_reg = RegistryParser()
    try:
        binary = parser_reg._find_binary()
        parser_reg._run_regripper(binary, Path("dummy_nonexistent.hive"), "ntuser")
        rip_parser = "yes"
    except RegRipperNotFoundError:
        rip_parser = "no"
    except Exception as e:
        rip_parser = f"no ({type(e).__name__})"
        
    version_rip = "Unknown"
    _, wsl_out, wsl_err, _ = run_cmd(["wsl", "perl", "/usr/lib/regripper/rip.pl", "-h"])
    m = re.search(r"Rip v\.([\d.]+)", (wsl_out or "") + (wsl_err or ""))
    if m:
        version_rip = m.group(1)
        
    results["RegRipper"] = {
        "direct": rip_direct,
        "shell": rip_shell,
        "parser": rip_parser,
        "version": version_rip,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 7. Hindsight Check
    # ----------------------------------------------------
    print("Checking Hindsight...")
    hindsight_script = None
    try:
        python_dir = Path(sys.executable).parent
        scripts_dir = python_dir / "Scripts"
        hindsight_py = scripts_dir / "hindsight.py"
        if hindsight_py.exists():
            hindsight_script = str(hindsight_py)
    except Exception:
        pass

    if not hindsight_script:
        hindsight_script = shutil.which("hindsight.py")

    if hindsight_script:
        rc, stdout, stderr, exc = run_cmd([sys.executable, hindsight_script, "--help"])
        hindsight_direct = "FOUND" if exc is None else "NOT FOUND"
        if exc:
            hindsight_direct = f"NOT FOUND ({type(exc).__name__})"
        elif rc != 0:
            hindsight_direct = f"FOUND BUT ERRORED (exit code {rc})"
    else:
        hindsight_direct = "NOT FOUND (FileNotFoundError)"
        rc, stdout, stderr, exc = None, "", "", FileNotFoundError("hindsight.py not found on PATH")

    s_rc, s_out, s_err, s_exc = run_cmd("hindsight.py --help", shell=True)
    hindsight_shell = "yes" if s_exc is None and (s_rc == 0 or "hindsight.py" in (s_out + s_err)) else "no"

    parser_browser = BrowserParser()
    try:
        parser_browser._run_hindsight(Path("dummy_nonexistent"), Path("dummy_out"))
        hindsight_parser = "yes"
    except HindsightExecutionError:
        hindsight_parser = "yes"  # Reached binary, failed on dummy path (expected)
    except HindsightNotFoundError:
        hindsight_parser = "no"
    except Exception as e:
        hindsight_parser = f"no ({type(e).__name__})"

    version_hindsight = "Unknown"
    if hindsight_script:
        _, h_out, h_err, _ = run_cmd([sys.executable, hindsight_script, "--help"])
        m = re.search(r"Hindsight v([\d\.]+)", (h_out or "") + (h_err or ""))
        if m:
            version_hindsight = m.group(1)

    results["Hindsight"] = {
        "direct": hindsight_direct,
        "shell": hindsight_shell,
        "parser": hindsight_parser,
        "version": version_hindsight,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # ----------------------------------------------------
    # 8. Sleuth Kit (TSK) Check
    # ----------------------------------------------------
    print("Checking Sleuth Kit (TSK)...")
    parser_fs = FilesystemParser()
    try:
        fls_bin = parser_fs._find_binary(parser_fs._FLS_BINARIES, "fls")
        rc, stdout, stderr, exc = run_cmd([fls_bin, "-V"])
        tsk_direct = "FOUND" if exc is None else "NOT FOUND"
        if exc:
            tsk_direct = f"NOT FOUND ({type(exc).__name__})"
        elif rc != 0:
            tsk_direct = f"FOUND BUT ERRORED (exit code {rc})"
    except Exception as e:
        tsk_direct = f"NOT FOUND ({type(e).__name__})"
        fls_bin = None
        rc, stdout, stderr, exc = None, "", "", e

    s_rc, s_out, s_err, s_exc = run_cmd("fls -V", shell=True)
    tsk_shell = "yes" if s_exc is None and ("Sleuth Kit" in (s_out + s_err) or s_rc == 0) else "no"

    try:
        fls_bin_test = parser_fs._find_binary(parser_fs._FLS_BINARIES, "fls")
        parser_fs._run_fls(fls_bin_test, Path("dummy_nonexistent"))
        tsk_parser = "yes"
    except TSKExecutionError:
        tsk_parser = "yes"  # Reached binary, failed on dummy path (expected)
    except TSKNotFoundError:
        tsk_parser = "no"
    except Exception as e:
        tsk_parser = f"no ({type(e).__name__})"

    version_tsk = "Unknown"
    if fls_bin:
        _, t_out, t_err, _ = run_cmd([fls_bin, "-V"])
        m = re.search(r"ver\s+([\d\.]+)", (t_out or "") + (t_err or ""))
        if m:
            version_tsk = m.group(1)

    results["Sleuth Kit (TSK)"] = {
        "direct": tsk_direct,
        "shell": tsk_shell,
        "parser": tsk_parser,
        "version": version_tsk,
        "error": str(exc) if exc else (stderr.strip() if rc != 0 else "")
    }

    # Print Report per tool
    print("\nDetailed Tool Connectivity Report:")
    print("==================================")
    for tool, data in results.items():
        print(f"Tool: {tool}")
        print(f"  Direct Subprocess (shell=False): {data['direct']}")
        if data['error']:
            print(f"  Subprocess Error/Output: {data['error']}")
        print(f"  Detected Version: {data['version']}")
        print("-" * 40)

    # Print Summary Table
    print("\nFinal Summary Table:")
    print("====================")
    header = f"{'Tool Name':<17} | {'Shell-Reachable':<15} | {'Parser-Reachable':<16} | {'Version Detected':<16} | {'Error Message'}"
    print(header)
    print("-" * len(header))
    for tool, data in results.items():
        err_msg = data['error'].replace('\n', ' ') if data['error'] else "None"
        if len(err_msg) > 40:
            err_msg = err_msg[:37] + "..."
        print(f"{tool:<17} | {data['shell']:<15} | {data['parser']:<16} | {data['version']:<16} | {err_msg}")
        
    # Determine exit code. If any required parser fails reachability, exit non-zero.
    has_failed = False
    for tool, data in results.items():
        # Perl doesn't have parser integration directly.
        # For other tools, if the parser cannot reach it, it is a deployment failure.
        if data['parser'] == "no" and tool != "Perl":
            has_failed = True
            
    if has_failed:
        print("\n[RESULT] Pre-deployment connectivity check: FAILED (Some tools are not reachable).")
        sys.exit(1)
    else:
        print("\n[RESULT] Pre-deployment connectivity check: PASSED (All tools are reachable).")
        sys.exit(0)

if __name__ == "__main__":
    main()
