import sys, os
sys.path.insert(0, ".")
import psycopg2
from minio import Minio
from config.settings import settings

print("=== LIVE INFRASTRUCTURE INITIALIZATION ===")

# 1. PostgreSQL setup
pg_user = os.getenv("POSTGRES_USER", settings.postgres_user)
pg_pass = os.getenv("POSTGRES_PASSWORD", settings.postgres_password)

try:
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database="postgres",
        user=pg_user,
        password=pg_pass,
        connect_timeout=3
    )
except Exception:
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database="postgres",
        user=os.getenv("USERNAME", "Sudeep"),
        connect_timeout=3
    )

conn.autocommit = True
cur = conn.cursor()
cur.execute("SELECT 1 FROM pg_database WHERE datname='argus';")
if cur.fetchone():
    cur.execute("DROP DATABASE argus;")
cur.execute("CREATE DATABASE argus WITH TEMPLATE template0 ENCODING 'UTF8';")
print("  [PG] Created database 'argus' with UTF8 encoding.")

try:
    cur.execute("CREATE USER argus_user WITH PASSWORD 'argus_dev' SUPERUSER;")
except Exception:
    pass
cur.execute("GRANT ALL PRIVILEGES ON DATABASE argus TO argus_user;")
conn.close()

# Apply schema to argus database
try:
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=pg_user,
        password=pg_pass,
        connect_timeout=3
    )
except Exception:
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=os.getenv("USERNAME", "Sudeep"),
        connect_timeout=3
    )

cur = conn.cursor()
cur.execute("SET client_encoding TO 'UTF8';")
with open("seed/postgres_init.sql", "r", encoding="utf-8") as f:
    sql = f.read()
cur.execute(sql)
conn.commit()

cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;")
tables = [r[0] for r in cur.fetchall()]
print(f"  [PG] Applied postgres_init.sql. Active tables: {tables}")
conn.close()

# 2. MinIO setup
m_host = settings.minio_endpoint.split("://")[-1]

client = None
for user, pwd in [
    (settings.minio_access_key, settings.minio_secret_key),
    ("minioadmin", "minioadmin"),
    ("argus_minio", "argus_minio_dev")
]:
    try:
        c = Minio(m_host, access_key=user, secret_key=pwd, secure=False)
        c.list_buckets()
        client = c
        print(f"  [MINIO] Connected with AccessKey: {user}")
        break
    except Exception:
        pass

if not client:
    raise RuntimeError("Could not connect to MinIO with any known credentials.")

buckets = ["argus-evidence", "argus-raw-evidence", "argus-encrypted-evidence"]
for b in buckets:
    if not client.bucket_exists(b):
        client.make_bucket(b)
        print(f"  [MINIO] Created bucket: {b}")
    else:
        print(f"  [MINIO] Bucket exists: {b}")

print("=== LIVE INFRASTRUCTURE READY ===")
