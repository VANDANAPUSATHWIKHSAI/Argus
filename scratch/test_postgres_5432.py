import psycopg2
import sys

def check_5432():
    print("Testing read-only connection to PostgreSQL on port 5432...")
    
    # Try 1: with argus_user / argus_dev on port 5432
    try:
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="argus",
            user="argus_user",
            password="argus_dev"
        )
        print("SUCCESS: Connected to 'argus' database on port 5432 as 'argus_user'!")
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
        tables = [row[0] for row in cur.fetchall()]
        print(f"Tables in 'argus' DB (port 5432): {tables}")
        conn.close()
        return True, "argus_user/5432"
    except Exception as e:
        print(f"Attempt 1 (argus_user/argus_dev on db=argus, port=5432) failed: {e}")

    # Try 2: with default postgres user on port 5432 to list databases and roles
    try:
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="postgres",
            user="postgres"
        )
        print("SUCCESS: Connected to 'postgres' database on port 5432 as 'postgres'!")
        cur = conn.cursor()
        cur.execute("SELECT datname FROM pg_database;")
        dbs = [row[0] for row in cur.fetchall()]
        print(f"Databases on port 5432: {dbs}")
        cur.execute("SELECT rolname FROM pg_roles;")
        roles = [row[0] for row in cur.fetchall()]
        print(f"Roles on port 5432: {roles}")
        conn.close()
        return False, "postgres_super_user_exists"
    except Exception as e:
        print(f"Attempt 2 (postgres on port=5432) failed: {e}")

    return False, "failed"

if __name__ == "__main__":
    check_5432()
