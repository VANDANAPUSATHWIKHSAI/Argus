import sys
import os
import shutil
import subprocess
from pathlib import Path

project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter, check_fls_aff_support
from preprocessing.parsers.filesystem_parser import FilesystemParser

def run_validation():
    print("=== ARGUS AFF SUPPORT — CRITICAL VALIDATION ===")
    
    # A. Capability
    fls_bin = shutil.which("fls") or shutil.which("fls.exe")
    if not fls_bin:
        tsk_dir = project_root / "tsk"
        if tsk_dir.exists():
            for folder in tsk_dir.iterdir():
                if folder.is_dir() and folder.name.startswith("sleuthkit-"):
                    bin_dir = folder / "bin"
                    if bin_dir.exists():
                        fls_bin = shutil.which("fls", path=str(bin_dir)) or shutil.which("fls.exe", path=str(bin_dir))
                        if fls_bin:
                            break

    print(f"\nA. Executable Capability Audit:")
    print(f"Detected fls binary: {fls_bin}")
    if fls_bin:
        res = subprocess.run([fls_bin, "-i", "list"], capture_output=True, text=True, timeout=10)
        print("fls -i list stdout/stderr:")
        print(res.stdout or res.stderr)
    
    has_aff_capability = check_fls_aff_support()
    print(f"check_fls_aff_support() result: {has_aff_capability}")

    # B. Direct AFF execution
    raw_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")
    aff0_path = raw_dir / "ntfs1-gen0.aff"
    aff1_path = raw_dir / "ntfs1-gen1.aff"

    print(f"\nB. Direct Executable Execution:")
    if fls_bin and has_aff_capability:
        for p in (aff0_path, aff1_path):
            cmd = [fls_bin, "-i", "afflib", "-r", str(p)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            lines = [l for l in r.stdout.splitlines() if l.strip()]
            print(f"Direct fls on {p.name}: Returncode {r.returncode}, Output lines: {len(lines)}")
    else:
        print("Installed fls binary does not support AFF (libaff missing from fls build). Safeguard active.")

    # C. ARGUS FilesystemParser execution
    print(f"\nC. ARGUS FilesystemParser Execution:")
    parser = FilesystemParser()
    for p in (aff0_path, aff1_path):
        if p.exists():
            arts = parser.parse(str(p), f"ev-{p.name}")
            print(f"FilesystemParser.parse({p.name}) -> {len(arts)} Artifacts")

    # D. Router Decision
    print(f"\nD. Router Decision Audit:")
    router = ParserRouter()
    for p in (aff0_path, aff1_path):
        if p.exists():
            ev = Evidence(evidence_id=f"ev-{p.name}", case_id="case-aff-test", filename=p.name, file_path=str(p), uploaded_by="tester")
            res = router.determine_routing(ev)
            print(f"Route({p.name}) -> status: {res.status}, target_parser: {res.target_parser}, reason: {res.reason}")

if __name__ == "__main__":
    run_validation()
