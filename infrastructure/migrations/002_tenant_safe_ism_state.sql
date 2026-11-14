-- ==============================================================================
-- ARGUS MIGRATION 002: Tenant-Safe ISM Checkpoint Persistence (Corrected & Non-Destructive)
-- Description:
--   Transforms ism_state primary key from (case_id, stage) to (tenant_id, case_id, stage).
--   Determines tenant ownership using unambiguous validation between checkpoint JSONB
--   metadata and cases table tenant mapping.
--   Enforces explicit pre-migration contradiction checks:
--     - Aborts if checkpoint JSONB tenant contradicts linked case tenant.
--     - Aborts if case mappings are ambiguous or multiple.
--     - Only permits JSONB tenant fallback when no case record exists.
--   Fails closed (aborts transaction) if any record has an unresolvable tenant.
--   Removes unsafe implicit default tenant assignment (enforces NOT NULL with NO DEFAULT).
--   Preserves foreign key cascading behavior and 100% of historical checkpoint records.
-- ==============================================================================

BEGIN;

-- 1. Pre-Migration Verification
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ism_state') THEN
        RAISE EXCEPTION 'MIGRATION ABORTED: Table ism_state does not exist.';
    END IF;
END $$;

-- 2. Add tenant_id column if not present (nullable during backfill)
ALTER TABLE ism_state ADD COLUMN IF NOT EXISTS tenant_id TEXT;

-- 3. Explicit Pre-Migration Contradiction Check: Checkpoint JSON vs Authoritative Cases Mapping
DO $$
DECLARE
    v_contradiction_count INT;
    v_contradiction_details TEXT;
BEGIN
    SELECT COUNT(*) INTO v_contradiction_count
    FROM ism_state i
    INNER JOIN cases c ON i.case_id = c.case_id
    WHERE i.checkpoint->>'tenant_id' IS NOT NULL
      AND i.checkpoint->>'tenant_id' != ''
      AND c.tenant_id IS NOT NULL
      AND c.tenant_id != ''
      AND i.checkpoint->>'tenant_id' != c.tenant_id;

    IF v_contradiction_count > 0 THEN
        SELECT string_agg(format('case_id: %s, stage: %s (JSON tenant: %s vs Case tenant: %s)', case_id, stage, json_tenant, case_tenant), E'\n')
        INTO v_contradiction_details
        FROM (
            SELECT i.case_id, i.stage, i.checkpoint->>'tenant_id' AS json_tenant, c.tenant_id AS case_tenant
            FROM ism_state i
            INNER JOIN cases c ON i.case_id = c.case_id
            WHERE i.checkpoint->>'tenant_id' IS NOT NULL
              AND i.checkpoint->>'tenant_id' != ''
              AND c.tenant_id IS NOT NULL
              AND c.tenant_id != ''
              AND i.checkpoint->>'tenant_id' != c.tenant_id
            LIMIT 10
        ) sub;

        RAISE EXCEPTION E'MIGRATION ABORTED: Found % contradictory ism_state record(s) where checkpoint JSONB tenant conflicts with authoritative cases table tenant.\nContradictory samples:\n%\n\nDIAGNOSTIC: Silent selection of either tenant when ownership conflicts is strictly forbidden. Manual reconciliation is required.',
            v_contradiction_count, v_contradiction_details;
    END IF;
END $$;

-- 4. Ambiguity Check: Ensure No Ambiguous Multiple Case Mappings Exist
DO $$
DECLARE
    v_ambiguous_case_count INT;
    v_ambiguous_samples TEXT;
BEGIN
    SELECT COUNT(*) INTO v_ambiguous_case_count
    FROM (
        SELECT case_id
        FROM cases
        GROUP BY case_id
        HAVING COUNT(DISTINCT tenant_id) > 1
    ) sub;

    IF v_ambiguous_case_count > 0 THEN
        SELECT string_agg(format('case_id: %s (tenants: %s)', case_id, tenants), E'\n')
        INTO v_ambiguous_samples
        FROM (
            SELECT case_id, string_agg(DISTINCT tenant_id, ', ') AS tenants
            FROM cases
            GROUP BY case_id
            HAVING COUNT(DISTINCT tenant_id) > 1
            LIMIT 5
        ) sub;

        RAISE EXCEPTION E'MIGRATION ABORTED: Found % ambiguous case mapping(s) where a case_id maps to multiple tenants in cases table.\nAmbiguous samples:\n%\n\nDIAGNOSTIC: Cannot determine unambiguous tenant ownership.',
            v_ambiguous_case_count, v_ambiguous_samples;
    END IF;
END $$;

-- 5. Authoritative Multi-Source Tenant Backfill:
--    Pass A: Authoritative linked cases mapping (any non-empty JSON tenant was verified consistent in Step 3)
UPDATE ism_state i
SET tenant_id = c.tenant_id
FROM cases c
WHERE i.case_id = c.case_id
  AND c.tenant_id IS NOT NULL
  AND c.tenant_id != ''
  AND (i.tenant_id IS NULL OR i.tenant_id = '');

--    Pass B: Verified checkpoint JSONB tenant ONLY when NO authoritative case relationship exists
UPDATE ism_state i
SET tenant_id = i.checkpoint->>'tenant_id'
WHERE (i.tenant_id IS NULL OR i.tenant_id = '')
  AND i.checkpoint->>'tenant_id' IS NOT NULL
  AND i.checkpoint->>'tenant_id' != ''
  AND NOT EXISTS (
      SELECT 1 FROM cases c WHERE c.case_id = i.case_id
  );

-- 6. Fail-Closed Validation Gate: Reject Ambiguous or Unresolved Records
-- Never silently assign unresolvable records to 'default'.
DO $$
DECLARE
    v_unresolved_count INT;
BEGIN
    SELECT COUNT(*) INTO v_unresolved_count
    FROM ism_state
    WHERE tenant_id IS NULL OR tenant_id = '';

    IF v_unresolved_count > 0 THEN
        RAISE EXCEPTION 'MIGRATION ABORTED: Found % unresolvable ism_state records where tenant ownership cannot be determined unambiguously. Manual tenant reconciliation is required before applying composite primary key.', v_unresolved_count;
    END IF;
END $$;

-- 7. Duplicate Check on Candidate Composite Primary Key (tenant_id, case_id, stage)
DO $$
DECLARE
    v_dup_composite INT;
BEGIN
    SELECT COUNT(*) INTO v_dup_composite
    FROM (
        SELECT tenant_id, case_id, stage
        FROM ism_state
        GROUP BY tenant_id, case_id, stage
        HAVING COUNT(*) > 1
    ) sub;

    IF v_dup_composite > 0 THEN
        RAISE EXCEPTION 'MIGRATION ABORTED: Found % duplicate (tenant_id, case_id, stage) combination(s). Merging or deleting is forbidden without manual administrative authorization.', v_dup_composite;
    END IF;
END $$;

-- 8. Enforce NOT NULL Constraint WITHOUT Implicit Default
-- Removes unsafe implicit default tenant assignment to guarantee fail-closed behavior on writes.
ALTER TABLE ism_state ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ism_state ALTER COLUMN tenant_id DROP DEFAULT;

-- 9. Update Primary Key Constraint
ALTER TABLE ism_state DROP CONSTRAINT IF EXISTS ism_state_pkey;
ALTER TABLE ism_state ADD PRIMARY KEY (tenant_id, case_id, stage);

-- 10. Create Scoped Lookup Index
CREATE INDEX IF NOT EXISTS idx_ism_state_tenant_case ON ism_state (tenant_id, case_id, stage);

COMMIT;
