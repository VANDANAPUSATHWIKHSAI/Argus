import psycopg2
import os
import bcrypt
import time

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

conn = None
for _ in range(10):
    try:
        conn = psycopg2.connect(
            host=os.environ.get('POSTGRES_HOST', 'localhost'),
            port=os.environ.get('POSTGRES_PORT', '5433'),
            database=os.environ.get('POSTGRES_DB', 'argus'),
            user=os.environ.get('POSTGRES_USER', 'argus_user'),
            password=os.environ.get('POSTGRES_PASSWORD', 'argus_dev')
        )
        break
    except Exception as e:
        print("Waiting for Postgres...")
        time.sleep(2)

if not conn:
    print("Could not connect to Postgres")
    exit(1)

cur = conn.cursor()
cur.execute('''CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY, email VARCHAR, password_hash VARCHAR,
    role VARCHAR, name VARCHAR, phone VARCHAR, doj VARCHAR,
    tenant_id VARCHAR NOT NULL DEFAULT 'default'
)''')
cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id VARCHAR")
cur.execute("UPDATE users SET tenant_id = 'default' WHERE tenant_id IS NULL")
cur.execute("ALTER TABLE users ALTER COLUMN tenant_id SET DEFAULT 'default'")
cur.execute("ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL")

users = [
    ('admin', 'admin@argus.local', 'password123', 'admin', 'System Administrator', '+1-555-0100', '2025-01-01'),
    ('analyst', 'analyst@argus.local', 'password123', 'analyst', 'Junior Analyst', '+1-555-0101', '2025-01-15'),
    ('senior_analyst', 'senior@argus.local', 'password123', 'senior_analyst', 'Senior Analyst', '+1-555-0103', '2025-01-10'),
    ('auditor', 'auditor@argus.local', 'password123', 'auditor', 'Compliance Auditor', '+1-555-0106', '2025-01-20'),
    ('2', 'admin2@argus.local', 'password123', 'admin', 'System Administrator', '+1-555-0100', '2025-01-01'),
    ('4', 'vandanapusathwikhsai88@gmail.com', 'password123', 'analyst', 'sathwik', '+1-555-0101', '2025-01-15'),
    ('5', 'analyst5@argus.local', 'password123', 'analyst', 'Analyst 5', '+1-555-0102', '2025-01-15'),
    ('6', 'remakhat115@gmail.com', 'password123', 'senior_analyst', 'Senior Analyst 6', '+1-555-0103', '2025-01-10'),
    ('7', 'senior7@argus.local', 'password123', 'senior_analyst', 'Senior Analyst 7', '+1-555-0104', '2025-01-10'),
    ('8', 'senior8@argus.local', 'password123', 'senior_analyst', 'Senior Analyst 8', '+1-555-0105', '2025-01-10'),
    ('12', 'auditor12@argus.local', 'password123', 'auditor', 'Auditor 12', '+1-555-0106', '2025-01-20')
]

for uid, email, pwd, role, name, phone, doj in users:
    pwd_hash = get_password_hash(pwd)
    cur.execute('''
        INSERT INTO users (id, email, password_hash, role, name, phone, doj, tenant_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 'default')
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            password_hash = EXCLUDED.password_hash,
            role = EXCLUDED.role,
            name = EXCLUDED.name,
            phone = EXCLUDED.phone,
            doj = EXCLUDED.doj
    ''', (uid, email, pwd_hash, role, name, phone, doj))
    print(f"Upserted user: {uid} ({role}) - {email}")

conn.commit()
print("All users seeded and synced successfully!")
