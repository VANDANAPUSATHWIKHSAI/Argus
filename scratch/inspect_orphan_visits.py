import sqlite3

db_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("""
SELECT v.id, v.url, v.visit_time, v.from_visit, v.transition 
FROM visits v 
WHERE v.url NOT IN (SELECT id FROM urls)
LIMIT 10
""")
rows = cur.fetchall()
print("Sample orphan visits (url foreign key missing from urls table):")
for r in rows:
    print(r)
