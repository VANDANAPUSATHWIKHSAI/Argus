import ast
import os

TARGET_DIRS = [
    r"c:\Users\Sudeep\Downloads\Argus\Argus\preprocessing",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\forensic_analysis",
]

def audit_ast():
    findings = []
    for tdir in TARGET_DIRS:
        for root, dirs, files in os.walk(tdir):
            if "__pycache__" in root:
                continue
            for file in files:
                if not file.endswith(".py"):
                    continue
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        tree = ast.parse(f.read(), filename=file)
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Constant) and isinstance(node.value, str):
                            val = node.value
                            val_l = val.lower()
                            if any(term in val_l for term in [
                                "sudeep", "kumar", "ntfs", "nps", "mfr-desktop", 
                                "c:\\", "c:/", "users\\", "users/", ".eml", ".aff", ".e01",
                                "192.168.", "10.0.", "172.16.", "case-", "art-", "corr-"
                            ]):
                                rel = os.path.relpath(fpath, r"c:\Users\Sudeep\Downloads\Argus\Argus")
                                findings.append((rel, getattr(node, 'lineno', 0), val))
                except Exception as e:
                    pass
    return findings

if __name__ == "__main__":
    res = audit_ast()
    out_file = r"c:\Users\Sudeep\Downloads\Argus\Argus\scratch\ast_strings.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"Total findings: {len(res)}\n")
        for r in res:
            f.write(f"[{r[0]}:L{r[1]}] -> {repr(r[2])}\n")
    print(f"Written {len(res)} results to {out_file}")
