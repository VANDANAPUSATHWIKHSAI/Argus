-- ==============================================================================
-- ARGUS MIGRATION 003a: Ownership-Aware Evidence Tenant ID Introduction & Backfill
-- File: Argus/infrastructure/migrations/003a_evidence_tenant_id_backfill.sql
-- ==============================================================================

BEGIN;

-- 1. Metadata Tracking Table Setup
CREATE TABLE IF NOT EXISTS argus_migration_metadata (
    migration_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

DO $$
DECLARE
    v_col_exists BOOLEAN;
    v_col_type TEXT;
    v_col_nullable TEXT;
    v_existing_meta JSONB;
    v_conflict_count INT;
    v_conflict_samples TEXT;
    v_unresolved_count INT;
    v_total_evidence INT;
    v_backfilled_count INT;
BEGIN
    -- 2. Inspect Existing Migration Metadata
    SELECT metadata INTO v_existing_meta
    FROM argus_migration_metadata
    WHERE migration_id = '003a_evidence_tenant_id_backfill';

    -- 3. Inspect PostgreSQL Catalog for evidence.tenant_id
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'evidence' AND column_name = 'tenant_id'
    ) INTO v_col_exists;

    IF v_col_exists THEN
        SELECT data_type, is_nullable
        INTO v_col_type, v_col_nullable
        FROM information_schema.columns
        WHERE table_name = 'evidence' AND column_name = 'tenant_id';

        -- Validate Data Type (Must be text or varchar)
        IF v_col_type NOT IN ('text', 'character varying') THEN
            RAISE EXCEPTION 'MIGRATION ABORTED: Column evidence.tenant_id exists with unexpected data type: % (expected text or varchar)', v_col_type;
        END IF;

        -- 4. Check for Conflicting Pre-Existing Values vs Authoritative Cases
        SELECT COUNT(*) INTO v_conflict_count
        FROM evidence e
        JOIN cases c ON e.case_id = c.case_id
        WHERE e.tenant_id IS NOT NULL 
          AND e.tenant_id <> ''
          AND e.tenant_id <> c.tenant_id;

        IF v_conflict_count > 0 THEN
            SELECT string_agg(format('EID: %s, Case: %s, EvidenceTenant: %s, CaseTenant: %s', e.evidence_id, e.case_id, e.tenant_id, c.tenant_id), E'\n')
            INTO v_conflict_samples
            FROM evidence e
            JOIN cases c ON e.case_id = c.case_id
            WHERE e.tenant_id IS NOT NULL 
              AND e.tenant_id <> ''
              AND e.tenant_id <> c.tenant_id
            LIMIT 5;

            RAISE EXCEPTION E'MIGRATION ABORTED: Found % conflicting tenant value(s) in evidence table against authoritative cases.\nSamples:\n%\nOverwriting existing tenant ownership is strictly forbidden.',
                v_conflict_count, v_conflict_samples;
        END IF;
    ELSE
        -- Add Column Safely without Default
        EXECUTE 'ALTER TABLE evidence ADD COLUMN tenant_id TEXT';
    END IF;

    -- 5. Authoritative Derivation: Backfill missing tenant_id strictly from cases
    UPDATE evidence e
    SET tenant_id = c.tenant_id
    FROM cases c
    WHERE e.case_id = c.case_id
      AND (e.tenant_id IS NULL OR e.tenant_id = '');

    GET DIAGNOSTICS v_backfilled_count = ROW_COUNT;

    -- 6. Fail-Closed Validation Gate: Ensure zero unresolved tenants
    SELECT COUNT(*) INTO v_unresolved_count
    FROM evidence
    WHERE tenant_id IS NULL OR tenant_id = '';

    IF v_unresolved_count > 0 THEN
        RAISE EXCEPTION 'MIGRATION ABORTED: % evidence records have unresolved tenant ownership.', v_unresolved_count;
    END IF;

    -- 7. Enforce NOT NULL without Implicit Default
    EXECUTE 'ALTER TABLE evidence ALTER COLUMN tenant_id SET NOT NULL';
    EXECUTE 'ALTER TABLE evidence ALTER COLUMN tenant_id DROP DEFAULT';

    -- 8. Record Ownership Metadata Idempotently
    SELECT count(*) INTO v_total_evidence FROM evidence;

    IF v_existing_meta IS NULL THEN
        INSERT INTO argus_migration_metadata (migration_id, created_at, metadata)
        VALUES (
            '003a_evidence_tenant_id_backfill',
            NOW(),
            jsonb_build_object(
                'created_tenant_id_column', NOT v_col_exists,
                'column_existed_prior', v_col_exists,
                'total_evidence_rows', v_total_evidence,
                'backfilled_rows', v_backfilled_count,
                'completed_at', NOW()
            )
        );
    ELSE
        UPDATE argus_migration_metadata
        SET metadata = metadata || jsonb_build_object(
            're_verified_at', NOW(),
            'total_evidence_rows', v_total_evidence
        )
        WHERE migration_id = '003a_evidence_tenant_id_backfill';
    END IF;
END $$;

COMMIT;

