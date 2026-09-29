import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import psycopg2
from config.settings import settings

conn = psycopg2.connect(
    host=settings.postgres_host,
    port=settings.postgres_port,
    database=settings.postgres_db,
    user=settings.postgres_user,
    password=settings.postgres_password
)
cur = conn.cursor()
cur.execute("SELECT case_id, count(*) FROM fir_findings GROUP BY case_id")
print("fir_findings case breakdown:")
for r in cur.fetchall():
    print("  ", r)

cur.execute("SELECT layer, count(*) FROM fir_findings WHERE case_id = 'default_case' GROUP BY layer")
print("default_case layer breakdown:")
for r in cur.fetchall():
    print("  ", r)

conn.close()
