"""
ARGUS Production Migration Runner
Authoritative entry point for staged zero-downtime database migrations.
Enforces:
1. Explicit connection.autocommit = True for concurrent index operations.
2. Assertion that transaction status is TRANSACTION_STATUS_IDLE.
3. Proper SET ROLE to migration owner (disp_owner / argus_migrator).
4. Pre-creation detection and cleanup of interrupted/invalid indexes.
5. Post-creation catalog validation (indisvalid, indisready, indisunique, indpred IS NULL).
6. Bounded lock timeouts (SET LOCAL lock_timeout = '3s') for constraint attachments.
7. Two-phase constraint creation: ADD CONSTRAINT ... NOT VALID followed by VALIDATE CONSTRAINT.
8. Idempotent reruns and safe partial-failure recovery.
"""
import psycopg2
from psycopg2.extensions import TRANSACTION_STATUS_IDLE
import logging
import sys

logger = logging.getLogger("argus.migration_runner")

class MigrationExecutionError(Exception):
    pass

class MigrationRunner:
    def __init__(self, db_config, owner_role=None):
        self.db_config = db_config
        self.owner_role = owner_role

    def get_connection(self, autocommit=True):
        conn = psycopg2.connect(**self.db_config)
        conn.autocommit = autocommit
        return conn

    def run_migration_004(self, schema="public"):
        """
        Executes Migration 004: Staged Zero-Downtime Composite Foreign Keys.
        Ensures strict separation between non-transactional concurrent index DDL
        and transactional constraint attachments with lock timeouts.
        """
        logger.info("Starting Migration 004 in schema: %s", schema)
        conn = self.get_connection(autocommit=True)
        cur = conn.cursor()

        try:
            # Step 0: Verify Role and search_path
            if self.owner_role:
                cur.execute(f"SET ROLE {self.owner_role};")
            cur.execute(f"SET search_path TO {schema}, public;")

            # Step 1: Detect and safely drop invalid index if previously interrupted
            cur.execute("""
                SELECT c.relname, i.indisvalid
                FROM pg_index i
                JOIN pg_class c ON c.oid = i.indexrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'idx_cases_tenant_case_unique' 
                  AND n.nspname = %s;
            """, (schema,))
            row = cur.fetchone()
            if row:
                index_name, is_valid = row
                if not is_valid:
                    logger.warning("Detected invalid index %s. Dropping concurrently...", index_name)
                    # Verify TRANSACTION_STATUS_IDLE
                    if conn.get_transaction_status() != TRANSACTION_STATUS_IDLE:
                        raise MigrationExecutionError("Cannot run DROP INDEX CONCURRENTLY inside an active transaction!")
                    cur.execute(f"DROP INDEX CONCURRENTLY {schema}.idx_cases_tenant_case_unique;")
                    logger.info("Invalid index dropped successfully.")

            # Step 2: Create Unique Index Concurrently
            if conn.get_transaction_status() != TRANSACTION_STATUS_IDLE:
                raise MigrationExecutionError("Cannot run CREATE INDEX CONCURRENTLY inside an active transaction!")

            logger.info("Creating unique index idx_cases_tenant_case_unique concurrently...")
            cur.execute(f"""
                CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_tenant_case_unique
                ON {schema}.cases (tenant_id, case_id);
            """)

            # Step 3: Catalog verification of index validity, readiness, uniqueness, and predicate
            cur.execute("""
                SELECT 
                    i.indisvalid,
                    i.indisready,
                    i.indisunique,
                    (i.indpred IS NULL) AS is_unpredicated,
                    pg_get_indexdef(i.indexrelid)
                FROM pg_index i
                JOIN pg_class c ON c.oid = i.indexrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'idx_cases_tenant_case_unique' 
                  AND n.nspname = %s;
            """, (schema,))
            idx_meta = cur.fetchone()
            if not idx_meta:
                raise MigrationExecutionError("Index idx_cases_tenant_case_unique not found in catalog after creation!")

            indisvalid, indisready, indisunique, is_unpredicated, index_def = idx_meta
            if not (indisvalid and indisready and indisunique and is_unpredicated):
                raise MigrationExecutionError(f"Index failed catalog integrity checks: valid={indisvalid}, ready={indisready}, unique={indisunique}, unpredicated={is_unpredicated}")

            logger.info("Index verified: valid=%s, ready=%s, unique=%s, def=%s", indisvalid, indisready, indisunique, index_def)

            # Step 4: Attach Unique Constraint Using Index (Short Catalog Lock with Lock Timeout)
            # Check if constraint already exists
            cur.execute("""
                SELECT 1 FROM pg_constraint 
                WHERE conname = 'uq_cases_tenant_case' 
                  AND connamespace = (SELECT oid FROM pg_namespace WHERE nspname = %s);
            """, (schema,))
            if not cur.fetchone():
                logger.info("Attaching unique constraint uq_cases_tenant_case using index...")
                cur.execute(f"""
                    BEGIN;
                    SET LOCAL lock_timeout = '3s';
                    SET LOCAL statement_timeout = '10s';
                    ALTER TABLE {schema}.cases
                    ADD CONSTRAINT uq_cases_tenant_case
                    UNIQUE USING INDEX idx_cases_tenant_case_unique;
                    COMMIT;
                """)
            else:
                logger.info("Constraint uq_cases_tenant_case already exists.")

            # Step 5: Add Composite Foreign Key as NOT VALID
            cur.execute("""
                SELECT convalidated FROM pg_constraint 
                WHERE conname = 'fk_evidence_tenant_case' 
                  AND connamespace = (SELECT oid FROM pg_namespace WHERE nspname = %s);
            """, (schema,))
            fk_status = cur.fetchone()

            if not fk_status:
                logger.info("Adding composite foreign key fk_evidence_tenant_case as NOT VALID...")
                cur.execute(f"""
                    BEGIN;
                    SET LOCAL lock_timeout = '3s';
                    SET LOCAL statement_timeout = '10s';
                    ALTER TABLE {schema}.evidence
                    ADD CONSTRAINT fk_evidence_tenant_case
                    FOREIGN KEY (tenant_id, case_id)
                    REFERENCES {schema}.cases (tenant_id, case_id)
                    ON DELETE RESTRICT
                    NOT VALID;
                    COMMIT;
                """)
                is_validated = False
            else:
                is_validated = fk_status[0]

            # Step 6: Validate Constraint Separately (Non-blocking table scan)
            if not is_validated:
                logger.info("Validating composite foreign key fk_evidence_tenant_case...")
                cur.execute(f"ALTER TABLE {schema}.evidence VALIDATE CONSTRAINT fk_evidence_tenant_case;")
                cur.execute("""
                    SELECT convalidated FROM pg_constraint 
                    WHERE conname = 'fk_evidence_tenant_case' 
                      AND connamespace = (SELECT oid FROM pg_namespace WHERE nspname = %s);
                """, (schema,))
                validated = cur.fetchone()[0]
                if not validated:
                    raise MigrationExecutionError("Foreign key fk_evidence_tenant_case validation failed!")
                logger.info("Foreign key successfully validated.")

            logger.info("Migration 004 completed successfully with zero downtime.")
            return True

        finally:
            if self.owner_role:
                cur.execute("RESET ROLE;")
            cur.close()
            conn.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print("Argus MigrationRunner loaded successfully.")

