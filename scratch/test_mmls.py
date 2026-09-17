import shutil
import subprocess
import re
from pathlib import Path

def discover_partition_offsets(image_path: Path) -> list[str]:
    mmls_bin = shutil.which("mmls") or shutil.which("mmls.exe")
    if not mmls_bin:
        project_root = Path(__file__).resolve().parents[1]
        tsk_dir = project_root / "tsk"
        if tsk_dir.exists():
            for folder in tsk_dir.iterdir():
                if folder.is_dir() and folder.name.startswith("sleuthkit-"):
                    bin_dir = folder / "bin"
                    if bin_dir.exists():
                        mmls_bin = shutil.which("mmls", path=str(bin_dir)) or shutil.which("mmls.exe", path=str(bin_dir))
                        if mmls_bin:
                            break

    if not mmls_bin:
        print("[MMLS WARNING] mmls binary not found")
        return ["0"]

    cmd = [mmls_bin, str(image_path)]
    print(f"Running mmls: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            print(f"[MMLS WARNING] mmls returned code {res.returncode}: {res.stderr}")
            return ["0"]

        offsets = []
        # Example mmls slot line:
        # 006:  001       0000065664   0001736831   0001671168   Basic data partition
        pattern = re.compile(r'^\s*\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$', re.MULTILINE)
        
        ignored_keywords = {"unallocated", "meta", "safety table", "gpt header", "partition table", "microsoft reserved partition"}

        for match in pattern.finditer(res.stdout):
            slot_type = match.group(1).lower()
            start_sector = match.group(2)
            desc = match.group(5).lower().strip()

            if slot_type in ("meta", "-------"):
                continue
            if any(kw in desc for kw in ignored_keywords):
                continue
            
            # Valid filesystem partition found!
            offset_val = str(int(start_sector))
            print(f"Found Partition: Slot={match.group(1)}, Start={offset_val}, Desc={match.group(5)}")
            offsets.append(offset_val)

        return offsets if offsets else ["0"]

    except Exception as e:
        print(f"[MMLS ERROR] {e}")
        return ["0"]

if __name__ == "__main__":
    img = Path(r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01")
    offsets = discover_partition_offsets(img)
    print("Discovered offsets:", offsets)
