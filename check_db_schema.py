import sys
sys.path.append('.')
from api.routes.auth import get_db_connection
with get_db_connection() as conn:
  with conn.cursor() as cur:
    cur.execute('SELECT column_name, is_nullable, data_type FROM information_schema.columns WHERE table_name = ''users''')
    for r in cur.fetchall(): print(r)
