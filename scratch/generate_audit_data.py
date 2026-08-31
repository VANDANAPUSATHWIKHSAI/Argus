import sys, os, time, hashlib, json
sys.path.insert(0, ".")
from pathlib import Path
from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter, _IMPLEMENTED_PARSERS, _SOURCE_PARSER_MAP

print("==================================================================")
print("ARGUS PHASE A.2.1 — RAW EVIDENCE PARSING METRICS")
print("==================================================================")

source_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")
router = ParserRouter()

file_results = []
t_total_start = time.perf_counter()

for p in sorted(source_dir.iterdir()):
    if p.is_file():
        src_bytes = p.read_bytes()
        sha256_before = hashlib.sha256(src_bytes).hexdigest()
        
        ev = Evidence(
            case_id="case-phase-a21",
            filename=p.name,
            file_path=str(p),
            raw_file_path=str(p),
            uploaded_by="verifier",
            sha256_hash=sha256_before,
            metadata={"size_bytes": len(src_bytes), "extension": p.suffix.lower()}
        )
        
        t_route_0 = time.perf_counter()
        res = router.determine_routing(ev)
        t_route_1 = time.perf_counter()
        
        t_parse_0 = time.perf_counter()
        records_count = 0
        error_msg = None
        
        if res.status == "ROUTED" and res.parser_instance:
            try:
                artifacts = res.parser_instance.parse(str(p), ev.evidence_id)
                records_count = len(artifacts)
            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
        else:
            error_msg = res.reason or f"Status={res.status}"
            
        t_parse_1 = time.perf_counter()
        
        sha256_after = hashlib.sha256(p.read_bytes()).hexdigest()
        integrity = "PASS" if sha256_before == sha256_after else "FAIL"
        
        route_time = (t_route_1 - t_route_0) * 1000 # ms
        parse_time = (t_parse_1 - t_parse_0) * 1000 # ms
        total_file_time = route_time + parse_time
        
        file_results.append({
            "filename": p.name,
            "size": len(src_bytes),
            "status": res.status,
            "parser": res.target_parser,
            "type": res.evidence_type,
            "method": res.detection_method,
            "records": records_count,
            "route_ms": route_time,
            "parse_ms": parse_time,
            "total_ms": total_file_time,
            "sha256_before": sha256_before,
            "sha256_after": sha256_after,
            "integrity": integrity,
            "notes": error_msg
        })

t_total_elapsed = time.perf_counter() - t_total_start

print("{:<16} | {:<10} | {:<8} | {:<18} | {:<8} | {:<10} | {:<5}".format(
    "FILE", "SIZE", "STATUS", "PARSER", "RECORDS", "TIME (ms)", "HASH"
))
print("-" * 88)
for r in file_results:
    print("{:<16} | {:<10} | {:<8} | {:<18} | {:<8} | {:<10.2f} | {:<5}".format(
        r["filename"], f"{r['size']} B", r["status"], r["parser"], r["records"], r["total_ms"], r["integrity"]
    ))

print("-" * 88)
print(f"Total Processing Time: {t_total_elapsed * 1000:.2f} ms ({t_total_elapsed:.4f} s)")
