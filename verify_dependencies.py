#!/usr/bin/env python3
"""
Argus Dependency Verification Script
====================================
Validates all requirements for production readiness:
1. Python packages
2. External binaries
3. Services availability
4. HuggingFace cache models

Usage:
    python verify_dependencies.py [--json]
"""

import os
import sys
import shutil
import socket
import json
import importlib.util
from pathlib import Path

REQUIRED_PYTHON_PACKAGES = [
    ("python-dotenv", "dotenv"),
    ("pydantic", "pydantic"),
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("requests", "requests"),
    ("httpx", "httpx"),
    ("cryptography", "cryptography"),
    ("minio", "minio"),
    ("psycopg2", "psycopg2"),
    ("asyncpg", "asyncpg"),
    ("docker", "docker"),
    ("pyclamd", "pyclamd"),
    ("google-re2", "re2"),
    ("torch", "torch"),
    ("transformers", "transformers"),
    ("gliner", "gliner"),
    ("rfc3161ng", "rfc3161ng"),
]

REQUIRED_BINARIES = [
    ("hayabusa", "Hayabusa EVTX parser"),
    ("zeek", "Zeek traffic analyzer"),
    ("suricata", "Suricata IDS"),
    ("perl", "Perl runtime"),
    ("rip.pl", "RegRipper script"),
    ("fls", "TSK file listing"),
    ("istat", "TSK inode status"),
]

REQUIRED_SERVICES = [
    ("PostgreSQL", "localhost", 5433),
    ("MinIO", "localhost", 9000),
    ("Neo4j", "localhost", 7687),
    ("Qdrant", "localhost", 6333),
    ("ClamAV", "localhost", 3310),
]

REQUIRED_MODELS = [
    ("gliner-community/gliner_medium-v2.5", "models--gliner-community--gliner_medium-v2.5"),
    ("protectai/deberta-v3-base-prompt-injection-v2", "models--protectai--deberta-v3-base-prompt-injection-v2"),
]


def check_python_package(import_name: str) -> tuple[bool, str]:
    try:
        spec = importlib.util.find_spec(import_name)
        if spec is None:
            return False, "Not Found"
        mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", "Installed (unknown version)")
        return True, version
    except Exception as e:
        return False, str(e)


def check_binary(name: str) -> tuple[bool, str]:
    path = shutil.which(name)
    if path:
        return True, path

    stem = name.split('.')[0]
    names_to_check = [name, f"{stem}.exe", f"{stem}.pl", f"{stem}.bat"]
    
    search_dirs = [
        Path("external_tools"),
        Path("../external_tools"),
        Path("tsk/sleuthkit-4.15.0-win32/bin"),
        Path("../Argus/tsk/sleuthkit-4.15.0-win32/bin")
    ]
    
    for sdir in search_dirs:
        if sdir.exists():
            for target_name in names_to_check:
                p = sdir / target_name
                if p.exists():
                    return True, str(p)
                found = list(sdir.rglob(target_name))
                if found:
                    return True, str(found[0])

    return False, "Not Found on PATH"


def check_service(host: str, port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        res = s.connect_ex((host, port))
        s.close()
        return res == 0
    except Exception:
        return False


def get_hf_cache_dir() -> Path:
    home = Path.home()
    return home / ".cache" / "huggingface" / "hub"


def check_model_cache(model_folder: str) -> tuple[bool, str]:
    cache_dir = get_hf_cache_dir()
    model_path = cache_dir / model_folder
    if model_path.exists():
        # Find if snapshots or refs exist
        snapshots = model_path / "snapshots"
        if snapshots.exists() and any(snapshots.iterdir()):
            return True, f"Cached at {model_path}"
    return False, "Not Found in local HF cache"


def main():
    json_mode = "--json" in sys.argv

    results = {
        "python_packages": {},
        "binaries": {},
        "services": {},
        "models": {},
        "healthy": True
    }

    # 1. Check Python packages
    for pkg_name, imp_name in REQUIRED_PYTHON_PACKAGES:
        ok, detail = check_python_package(imp_name)
        results["python_packages"][pkg_name] = {"ok": ok, "detail": detail}
        if not ok:
            results["healthy"] = False

    # 2. Check Forensic Binaries (Optional standalone tools; built-in Python parsers act as fallbacks)
    missing_binaries = []
    for name, desc in REQUIRED_BINARIES:
        ok, detail = check_binary(name)
        results["binaries"][name] = {"ok": ok, "detail": detail, "description": desc}
        if not ok:
            missing_binaries.append(name)

    # 3. Check Services
    for name, host, port in REQUIRED_SERVICES:
        ok = check_service(host, port)
        results["services"][name] = {"ok": ok, "port": port}
        if not ok:
            results["healthy"] = False

    # 4. Check Models
    for model_id, folder in REQUIRED_MODELS:
        ok, detail = check_model_cache(folder)
        results["models"][model_id] = {"ok": ok, "detail": detail}
        if not ok:
            results["healthy"] = False

    if json_mode:
        print(json.dumps(results, indent=2))
        sys.exit(0 if results["healthy"] else 1)

    # Human-readable CLI reporting
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    NC = "\033[0m"

    print(f"{BOLD}======================================================================{NC}")
    print(f"{BOLD}                 Argus Dependency Verification Report                 {NC}")
    print(f"{BOLD}======================================================================{NC}")

    print(f"\n{BOLD}[1] Python Packages Check{NC}")
    for name, data in results["python_packages"].items():
        status = f"{GREEN}OK{NC}" if data["ok"] else f"{RED}FAIL{NC}"
        print(f"  [{status}] {name:<20} : {data['detail']}")

    print(f"\n{BOLD}[2] Forensic Binaries Check (Optional CLI Binaries){NC}")
    for name, data in results["binaries"].items():
        status = f"{GREEN}OK{NC}" if data["ok"] else f"{YELLOW}OPTIONAL{NC}"
        print(f"  [{status}] {name:<12} ({data['description']}) : {data['detail']}")

    print(f"\n{BOLD}[3] External Docker Services (Health Check){NC}")
    for name, data in results["services"].items():
        status = f"{GREEN}ONLINE{NC}" if data["ok"] else f"{YELLOW}OFFLINE{NC}"
        print(f"  [{status:<8}] {name:<12} (Port {data['port']})")

    print(f"\n{BOLD}[4] Pretrained Models (Local Cache Check){NC}")
    for name, data in results["models"].items():
        status = f"{GREEN}FOUND{NC}" if data["ok"] else f"{YELLOW}MISSING{NC}"
        print(f"  [{status:<8}] {name:<46} : {data['detail']}")

    print(f"\n{BOLD}======================================================================{NC}")
    if results["healthy"]:
        if missing_binaries:
            print(f"{GREEN}{BOLD}STATUS: HEALTHY — Argus Python Core, AI Models, & Docker Services are Ready!{NC}")
            print(f"  {YELLOW}(Note: Optional external binaries missing: {', '.join(missing_binaries)}; built-in Python fallbacks will be used.){NC}")
        else:
            print(f"{GREEN}{BOLD}STATUS: HEALTHY — Argus is fully ready for production!{NC}")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}STATUS: UNHEALTHY — Missing critical Python packages, AI models, or microservices!{NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
