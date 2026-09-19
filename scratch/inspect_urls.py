import sqlite3, os
from datetime import datetime, timezone

path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"
conn = sqlite3.connect(path)
cur = conn.cursor()

cur.execute("SELECT count(*) FROM urls")
print("urls count:", cur.fetchone()[0])

cur.execute("SELECT id, url, title, visit_count, typed_count, last_visit_time FROM urls LIMIT 10")
for row in cur.fetchall():
    url_id, url, title, visit_count, typed_count, last_visit_time = row
    # WebKit timestamp (microseconds since 1601-01-01)
    secs = (last_visit_time / 1000000.0) - 11644473600.0 if last_visit_time else 0
    dt = datetime.fromtimestamp(secs, tz=timezone.utc) if secs > 0 else None
    print(f"Row: ID={url_id}, URL={url}, Title={title}, Visits={visit_count}, LastVisit={dt}")
