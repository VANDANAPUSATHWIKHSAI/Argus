import os
import sqlite3
import hashlib
import json

db_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"

print(f"File path: {db_path}")
print(f"Exists: {os.path.exists(db_path)}")
size = os.path.getsize(db_path)
print(f"File size: {size} bytes")

with open(db_path, "rb") as f:
    sha256 = hashlib.sha256(f.read()).hexdigest()
print(f"SHA-256: {sha256}")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

# SQLite PRAGMA checks
cur.execute("PRAGMA integrity_check;")
integrity = cur.fetchall()
print(f"SQLite Integrity Check: {integrity}")

cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [r[0] for r in cur.fetchall()]
print(f"Tables: {tables}")

for t in tables:
    cur.execute(f"SELECT COUNT(*) FROM `{t}`")
    cnt = cur.fetchone()[0]
    print(f"Table '{t}': {cnt} rows")

print("\n--- SCHEMAS ---")
for t in ['urls', 'visits', 'moz_places', 'moz_historyvisits']:
    if t in tables:
        cur.execute(f"PRAGMA table_info(`{t}`);")
        cols = cur.fetchall()
        print(f"\nTable '{t}' columns:")
        for c in cols:
            print(f"  {c[1]} ({c[2]})")
