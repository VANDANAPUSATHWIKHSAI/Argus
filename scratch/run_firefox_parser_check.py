import sys, os
sys.path.insert(0, os.getcwd())

import sqlite3
from preprocessing.parsers.firefox_parser import FirefoxParser

db_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"

parser = FirefoxParser()
artifacts = parser.parse(db_path, evidence_id="ev-firefox-001")

print(f"Total parsed artifacts: {len(artifacts)}")

conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM visits v JOIN urls u ON u.id = v.url")
join_count = cur.fetchone()[0]
print(f"JOIN visits & urls row count: {join_count}")

cur.execute("SELECT COUNT(*) FROM visits")
visits_count = cur.fetchone()[0]
print(f"Visits table total rows: {visits_count}")

cur.execute("SELECT COUNT(*) FROM urls")
urls_count = cur.fetchone()[0]
print(f"Urls table total rows: {urls_count}")

# Check unjoined visits
cur.execute("SELECT COUNT(*) FROM visits WHERE url NOT IN (SELECT id FROM urls)")
orphan_visits = cur.fetchone()[0]
print(f"Orphan visits (url id not in urls table): {orphan_visits}")

# Check unjoined urls (urls with 0 visits in visits table)
cur.execute("SELECT COUNT(*) FROM urls WHERE id NOT IN (SELECT url FROM visits)")
urls_without_visits = cur.fetchone()[0]
print(f"URLs with 0 visits in visits table: {urls_without_visits}")

# Print sample artifact details
if artifacts:
    print("\nFirst artifact sample:")
    a0 = artifacts[0]
    print(f"Evidence ID: {a0.evidence_id}")
    print(f"Source Tool: {a0.source_tool}")
    print(f"Type: {a0.artifact_type}")
    print(f"Timestamp: {a0.timestamp} (Type: {a0.timestamp_type})")
    print(f"Summary: {a0.event_summary}")
    print(f"Normalized: {a0.normalized_fields}")
    print(f"Raw Fields sample keys: {list(a0.raw_fields.keys())}")
