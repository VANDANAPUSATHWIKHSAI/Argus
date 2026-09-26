import sys
sys.path.append('.')
from api.routes.auth import get_db_connection
with get_db_connection() as conn:
  with conn.cursor() as cur:
    cur.execute('SELECT id FROM users')
    print([r[0] for r in cur.fetchall()])
