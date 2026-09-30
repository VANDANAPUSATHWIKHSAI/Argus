import sys
sys.path.append('.')
from api.routes.auth import get_db_connection
with get_db_connection() as conn:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT tc.table_name, kcu.column_name, ccu.table_name AS foreign_table_name, ccu.column_name AS foreign_column_name 
            FROM information_schema.table_constraints AS tc 
            JOIN information_schema.key_column_usage AS kcu ON tc.constraint_name = kcu.constraint_name 
            JOIN information_schema.constraint_column_usage AS ccu ON ccu.constraint_name = tc.constraint_name 
            WHERE tc.constraint_type = 'FOREIGN KEY';
        """)
        print("--- FOREIGN KEYS ---")
        for r in cur.fetchall(): print(r)



