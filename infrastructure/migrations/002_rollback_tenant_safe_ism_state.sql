-- ==============================================================================
-- ARGUS ROLLBACK 002: Tenant-Safe ISM Checkpoint Persistence (Guarded & Non-Destructive)
-- Description:
--   Rolls back ism_state composite primary key to legacy (case_id, stage).
--   GUARANTEE: NEVER automatically deletes or merges cross-tenant checkpoints.
--   Fails closed (aborts transaction) if multiple tenants share any (case_id, stage).
-- ==============================================================================

BEGIN;

-- 1. Check for Cross-Tenant Collisions on (case_id, stage)
DO $$
DECLARE
    v_collision_count INT;
    v_collision_details TEXT;
BEGIN
    SELECT COUNT(*) INTO v_collision_count
    FROM (
        SELECT case_id, stage
        FROM ism_state
        GROUP BY case_id, stage
        HAVING COUNT(DISTINCT tenant_id) > 1
    ) sub;

    IF v_collision_count > 0 THEN
        SELECT string_agg(format('case_id: %s, stage: %s (tenants: %s)', case_id, stage, tenants), E'\n')
        INTO v_collision_details
        FROM (
            SELECT case_id, stage, string_agg(DISTINCT tenant_id, ', ') as tenants
            FROM ism_state
            GROUP BY case_id, stage
            HAVING COUNT(DISTINCT tenant_id) > 1
            LIMIT 5
        ) sub;

        RAISE EXCEPTION E'ROLLBACK ABORTED: Found % cross-tenant collision(s) on (case_id, stage).\nColliding samples:\n%\n\nDIAGNOSTIC: The legacy schema PRIMARY KEY (case_id, stage) cannot represent multiple tenants with identical case IDs and stages. Automatically deleting or merging these records would permanently destroy tenant investigation state, violating ARGUS forensic immutability.\n\nMANUAL RECOVERY PROCEDURE:\n1. Export colliding tenant checkpoints to archive storage.\n2. Reassign colliding case IDs to tenant-unique identifiers.\n3. Re-run this rollback script only after zero collisions exist.',
            v_collision_count, v_collision_details;
    END IF;
END $$;

-- 2. Drop Scoped Index
DROP INDEX IF EXISTS idx_ism_state_tenant_case;

-- 3. Replace Composite Primary Key with Legacy Primary Key
ALTER TABLE ism_state DROP CONSTRAINT IF EXISTS ism_state_pkey;
ALTER TABLE ism_state ADD PRIMARY KEY (case_id, stage);

-- 4. Drop tenant_id Column
ALTER TABLE ism_state DROP COLUMN IF EXISTS tenant_id;

COMMIT;
