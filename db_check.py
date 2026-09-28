from config.settings import settings
import psycopg2

try:
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password
    )
    cur = conn.cursor()
    cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'cases' AND column_name = 'case_id';")
    print(cur.fetchone())
    conn.close()
except Exception as e:
    print(e)
