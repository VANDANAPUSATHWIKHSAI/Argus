-- ==============================================================================
-- ARGUS MIGRATION 003: Tenant-Scoped Evidence Idempotency Unique Index (Ownership-Safe & Non-Destructive)
-- Description:
--   Enforces per-tenant and per-case evidence uniqueness at the database level:
--     CREATE UNIQUE INDEX idx_evidence_tenant_case_sha256_unique ON evidence (tenant_id, case_id, sha256_hash);
--   SCHEMA DEPENDENCY & OWNERSHIP SAFETY:
--     Records explicit migration ownership of evidence.tenant_id in argus_migration_metadata.
--     Rollback is strictly restricted from dropping tenant_id if the column pre-existed.
--   CONTRADICTION SAFETY:
--     Aborts migration if evidence metadata tenant contradicts authoritative cases tenant.
--   FAIL-CLOSED INTEGRITY:
--     Enforces tenant_id NOT NULL with NO IMPLICIT DEFAULT.
--     Guards against existing duplicate conflicts, aborting rather than destroying forensic evidence.
-- ==============================================================================

BEGIN;

-- 1. Create Migration Metadata Tracking Table
CREATE TABLE IF NOT EXISTS argus_migration_metadata (
    migration_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- 2. Determine and Record Column Pre-Existence & Ownership
DO $$
DECLARE
    v_col_existed BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'evidence' AND column_name = 'tenant_id'
    ) INTO v_col_existed;

    INSERT INTO argus_migration_metadata (migration_id, created_at, metadata)
    VALUES (
        '003_evidence_tenant_case_sha256_unique',
        NOW(),
        jsonb_build_object(
            'created_tenant_id_column', NOT v_col_existed,
            'column_existed_prior', v_col_existed,
            'table_name', 'evidence',
            'column_name', 'tenant_id'
        )
    )
    ON CONFLICT (migration_id) DO UPDATE SET
        metadata = EXCLUDED.metadata;
END $$;

-- 3. Ensure tenant_id column exists on evidence
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS tenant_id TEXT;

-- 4. Pre-Migration Contradiction Check: Metadata Tenant vs Authoritative Cases Tenant
DO $$
DECLARE
    v_ev_contradiction INT;
    v_ev_samples TEXT;
BEGIN
    SELECT COUNT(*) INTO v_ev_contradiction
    FROM evidence e
    INNER JOIN cases c ON e.case_id = c.case_id
    WHERE e.metadata->>'tenant_id' IS NOT NULL
      AND e.metadata->>'tenant_id' != ''
      AND c.tenant_id IS NOT NULL
      AND c.tenant_id != ''
      AND e.metadata->>'tenant_id' != c.tenant_id;

    IF v_ev_contradiction > 0 THEN
        SELECT string_agg(format('evidence_id: %s, case_id: %s (metadata tenant: %s vs case tenant: %s)', evidence_id, case_id, meta_tenant, case_tenant), E'\n')
        INTO v_ev_samples
        FROM (
            SELECT e.evidence_id, e.case_id, e.metadata->>'tenant_id' AS meta_tenant, c.tenant_id AS case_tenant
            FROM evidence e
            INNER JOIN cases c ON e.case_id = c.case_id
            WHERE e.metadata->>'tenant_id' IS NOT NULL
              AND e.metadata->>'tenant_id' != ''
              AND c.tenant_id IS NOT NULL
              AND c.tenant_id != ''
              AND e.metadata->>'tenant_id' != c.tenant_id
            LIMIT 5
        ) sub;

        RAISE EXCEPTION E'MIGRATION ABORTED: Found % contradictory evidence record(s) where metadata tenant conflicts with authoritative cases tenant.\nSamples:\n%\n\nDIAGNOSTIC: Silent resolution of conflicting tenant ownership is strictly forbidden.',
            v_ev_contradiction, v_ev_samples;
    END IF;
END $$;

-- 5. Authoritative Multi-Source Tenant Backfill
--    Pass A: Backfill from authoritative cases table
UPDATE evidence e
SET tenant_id = c.tenant_id
FROM cases c
WHERE e.case_id = c.case_id
  AND c.tenant_id IS NOT NULL
  AND c.tenant_id != ''
  AND (e.tenant_id IS NULL OR e.tenant_id = '');

--    Pass B: Validated metadata fallback ONLY when NO authoritative case exists
UPDATE evidence e
SET tenant_id = e.metadata->>'tenant_id'
WHERE (e.tenant_id IS NULL OR e.tenant_id = '')
  AND e.metadata->>'tenant_id' IS NOT NULL
  AND e.metadata->>'tenant_id' != ''
  AND NOT EXISTS (
      SELECT 1 FROM cases c WHERE c.case_id = e.case_id
  );

-- 6. Fail-Closed Validation Gate: Unresolved Tenants
DO $$
DECLARE
    v_unresolved_count INT;
BEGIN
    SELECT COUNT(*) INTO v_unresolved_count
    FROM evidence
    WHERE tenant_id IS NULL OR tenant_id = '';

    IF v_unresolved_count > 0 THEN
        RAISE EXCEPTION 'MIGRATION ABORTED: Found % evidence record(s) with unresolvable tenant_id. Cannot create tenant-scoped unique index.', v_unresolved_count;
    END IF;
END $$;

-- 7. Duplicate Check on Candidate Index (tenant_id, case_id, sha256_hash)
DO $$
DECLARE
    v_conflict_count INT;
    v_conflict_samples TEXT;
BEGIN
    SELECT COUNT(*) INTO v_conflict_count
    FROM (
        SELECT tenant_id, case_id, sha256_hash
        FROM evidence
        WHERE sha256_hash IS NOT NULL AND sha256_hash != ''
        GROUP BY tenant_id, case_id, sha256_hash
        HAVING COUNT(*) > 1
    ) sub;

    IF v_conflict_count > 0 THEN
        SELECT string_agg(format('Tenant: %s, Case: %s, SHA-256: %s, Count: %s', tenant_id, case_id, substring(sha256_hash from 1 for 12), cnt), E'\n')
        INTO v_conflict_samples
        FROM (
            SELECT tenant_id, case_id, sha256_hash, COUNT(*) as cnt
            FROM evidence
            WHERE sha256_hash IS NOT NULL AND sha256_hash != ''
            GROUP BY tenant_id, case_id, sha256_hash
            HAVING COUNT(*) > 1
            LIMIT 5
        ) sub;

        RAISE EXCEPTION E'MIGRATION ABORTED: Found % conflicting duplicate group(s) on (tenant_id, case_id, sha256_hash).\nConflicting samples:\n%\n\nDIAGNOSTIC: Automatic deletion or merging of evidence records is strictly forbidden to preserve forensic chain of custody.\nAdministrative resolution or archive isolation of historical duplicate evidence is required before applying this unique constraint.',
            v_conflict_count, v_conflict_samples;
    END IF;
END $$;

-- 8. Enforce NOT NULL on tenant_id WITHOUT Implicit Default
-- Fails closed on any future write that omits tenant_id.
ALTER TABLE evidence ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE evidence ALTER COLUMN tenant_id DROP DEFAULT;

-- 9. Create Tenant-Scoped Unique Index
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_tenant_case_sha256_unique
ON evidence (tenant_id, case_id, sha256_hash);

COMMIT;
