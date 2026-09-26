import sys
import os
import json
import psycopg2
from pathlib import Path

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from config.settings import settings

def main():
    json_path = os.path.join(ARGUS_ROOT, "scratch", "full_3286_sanitized_findings.json")
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"Loaded {len(data)} items from {json_path}")
    
    finding_ids = [item.get("finding_id") for item in data if item.get("finding_id")]
    print(f"Total finding_ids: {len(finding_ids)}")

    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password
    )
    cur = conn.cursor()
    
    cur.execute("SELECT count(*) FROM fir_findings WHERE finding_id = ANY(%s);", (finding_ids,))
    in_db_count = cur.fetchone()[0]
    print(f"Number of 3,286 finding_ids currently in postgresql 'fir_findings' table: {in_db_count}")
    
    # Also check case_id values in the JSON file:
    case_ids = set(item.get("case_id") for item in data)
    print(f"Unique case_ids in JSON file: {case_ids}")
    
    conn.close()

if __name__ == "__main__":
    main()
