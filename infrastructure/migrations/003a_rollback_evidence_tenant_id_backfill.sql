-- ==============================================================================
-- ARGUS MIGRATION 003a ROLLBACK: Safe Rollback of evidence.tenant_id
-- File: Argus/infrastructure/migrations/003a_rollback_evidence_tenant_id_backfill.sql
-- Description:
--   Safely rolls back Migration 003a ONLY if:
--   1. Migration metadata confirms the column was created by 003a.
--   2. Column did not pre-exist.
--   3. No dependent foreign keys or indexes depend on evidence.tenant_id.
--   4. Zero active application data was written post-migration.
-- ==============================================================================

BEGIN;

DO $$
DECLARE
    v_meta JSONB;
    v_created_by_mig BOOLEAN;
    v_col_existed_prior BOOLEAN;
    v_dep_count INT;
    v_active_app_rows INT;
BEGIN
    -- 1. Metadata Gate
    SELECT metadata INTO v_meta
    FROM argus_migration_metadata
    WHERE migration_id = '003a_evidence_tenant_id_backfill';

    IF v_meta IS NULL THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Missing migration metadata for 003a. Cannot verify ownership.';
    END IF;

    v_created_by_mig := COALESCE((v_meta->>'created_tenant_id_column')::boolean, false);
    v_col_existed_prior := COALESCE((v_meta->>'column_existed_prior')::boolean, true);

    -- 2. Pre-Existing Column Preservation Gate
    IF v_col_existed_prior OR NOT v_created_by_mig THEN
        RAISE NOTICE 'ROLLBACK NOTICE: Column evidence.tenant_id pre-existed Migration 003a. Preserving column and data.';
        RETURN;
    END IF;

    -- 3. Dependency Gate: Check for dependent constraints/indexes
    SELECT COUNT(*) INTO v_dep_count
    FROM (
        SELECT constraint_name FROM information_schema.constraint_column_usage
        WHERE table_name = 'evidence' AND column_name = 'tenant_id'
        UNION
        SELECT indexname FROM pg_indexes
        WHERE tablename = 'evidence' AND indexdef LIKE '%tenant_id%'
    ) sub;

    IF v_dep_count > 0 THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Column evidence.tenant_id is referenced by % active constraints/indexes. Drop dependents first.', v_dep_count;
    END IF;

    -- 4. Post-Migration Application Data Protection Gate
    SELECT COUNT(*) INTO v_active_app_rows
    FROM evidence
    WHERE tenant_id IS NOT NULL AND tenant_id <> '';

    IF v_active_app_rows > 0 THEN
        RAISE EXCEPTION 'ROLLBACK ABORTED: Column evidence.tenant_id contains % active rows. Dropping column would cause permanent loss of tenant ownership data.', v_active_app_rows;
    END IF;

    -- 5. Safe Column Drop
    EXECUTE 'ALTER TABLE evidence DROP COLUMN tenant_id';
    DELETE FROM argus_migration_metadata WHERE migration_id = '003a_evidence_tenant_id_backfill';
    RAISE NOTICE 'ROLLBACK COMPLETE: evidence.tenant_id was safely removed.';
END $$;

COMMIT;

