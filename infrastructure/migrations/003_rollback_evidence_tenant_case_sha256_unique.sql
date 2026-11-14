-- ==============================================================================
-- ARGUS ROLLBACK 003: Remove Tenant-Scoped Evidence Idempotency Index (Hardened & Data-Safe)
-- Description:
--   Drops the unique index idx_evidence_tenant_case_sha256_unique.
--   DATA-SAFE COLUMN TEARDOWN GATES:
--     1. Metadata Ownership Verification: Fails closed if ownership metadata is missing/corrupted.
--     2. Pre-Existing Column Preservation: Preserves column if it existed prior to migration 003.
--     3. Schema Dependency Check: Aborts if referenced by foreign keys, constraints, or indexes.
--     4. Post-Migration Data Preservation: Aborts if column contains active application tenant data.
--     5. Only permits column drop when sole ownership is proven, zero dependencies exist,
--        and no application data would be destroyed.
--   GUARANTEE: NEVER destroys forensic evidence, tenant assignments, or historical records.
-- ==============================================================================

BEGIN;

-- 1. Drop the unique index created by migration 003
DROP INDEX IF EXISTS idx_evidence_tenant_case_sha256_unique;

-- 2. Multi-Gate Hardened Column Teardown Gate
DO $$
DECLARE
    v_meta JSONB;
    v_created_by_mig BOOLEAN;
    v_col_exists BOOLEAN;
    v_dep_count INT;
    v_dep_names TEXT;
    v_app_data_count INT;
    v_migration_ts TIMESTAMPTZ;
BEGIN
    -- Check if column exists currently
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'evidence' AND column_name = 'tenant_id'
    ) INTO v_col_exists;

    IF NOT v_col_exists THEN
        -- Column does not exist; nothing to revert
        RETURN;
    END IF;

    -- Gate 1: Check metadata table and record
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'argus_migration_metadata') THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Migration metadata table argus_migration_metadata does not exist. Cannot prove ownership of evidence.tenant_id.';
    END IF;

    SELECT metadata, created_at INTO v_meta, v_migration_ts
    FROM argus_migration_metadata
    WHERE migration_id = '003_evidence_tenant_case_sha256_unique';

    IF v_meta IS NULL OR jsonb_typeof(v_meta) != 'object' THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Missing or corrupted migration ownership metadata for migration 003. Cannot determine if evidence.tenant_id was created by this migration. Preserving column to prevent forensic data loss.';
    END IF;

    v_created_by_mig := (v_meta->>'created_tenant_id_column')::BOOLEAN;

    -- Gate 2: Pre-Existing Column Preservation
    IF v_created_by_mig IS NOT TRUE THEN
        RAISE NOTICE 'ROLLBACK NOTICE: Column evidence.tenant_id existed prior to migration 003. Preserving column and all associated data.';
        RETURN;
    END IF;

    -- Gate 3: Schema Dependency Check (foreign keys, other indexes, constraints)
    SELECT COUNT(*), string_agg(conname, ', ')
    INTO v_dep_count, v_dep_names
    FROM pg_constraint
    WHERE conrelid = 'evidence'::regclass
      AND conname != 'evidence_pkey'
      AND conname != 'evidence_case_id_fkey'
      AND array_position(conkey, (
          SELECT attnum FROM pg_attribute 
          WHERE attrelid = 'evidence'::regclass AND attname = 'tenant_id'
      )) IS NOT NULL;

    IF v_dep_count > 0 THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Column evidence.tenant_id is referenced by active schema dependency [%]. Dropping column would violate relational integrity.', v_dep_names;
    END IF;

    -- Check for other indexes referencing tenant_id
    SELECT COUNT(*), string_agg(indexname, ', ')
    INTO v_dep_count, v_dep_names
    FROM pg_indexes
    WHERE tablename = 'evidence'
      AND indexname != 'idx_evidence_tenant_case_sha256_unique'
      AND indexdef LIKE '%tenant_id%';

    IF v_dep_count > 0 THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Column evidence.tenant_id is referenced by active index [%]. Dropping column would break database indexing.', v_dep_names;
    END IF;

    -- Gate 4: Post-Migration Application Data Check
    -- Check if column contains application tenant data written after or during migration
    SELECT COUNT(*) INTO v_app_data_count
    FROM evidence
    WHERE tenant_id IS NOT NULL AND tenant_id != '';

    IF v_app_data_count > 0 THEN
        RAISE EXCEPTION E'ROLLBACK ABORTED: Column evidence.tenant_id contains active application data (% record(s)).\nDIAGNOSTIC: Dropping the column would permanently destroy forensic tenant attribution established by application use.\nPreserve column or export data before rollback.',
            v_app_data_count;
    END IF;

    -- Gate 5: Safe Removal (Sole ownership proven, 0 dependencies, 0 application data)
    EXECUTE 'ALTER TABLE evidence DROP COLUMN tenant_id;';
    RAISE NOTICE 'ROLLBACK NOTICE: Column evidence.tenant_id was created by migration 003, had zero dependencies and zero application data, and was safely dropped.';
END $$;

-- 3. Remove migration record only if column was safely removed or preserved
DELETE FROM argus_migration_metadata
WHERE migration_id = '003_evidence_tenant_case_sha256_unique';

COMMIT;
