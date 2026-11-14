-- ==============================================================================
-- ARGUS MIGRATION 004 ROLLBACK: Safe Rollback of Composite Foreign Keys
-- File: Argus/infrastructure/migrations/004_rollback_composite_foreign_keys.sql
-- ==============================================================================

BEGIN;

-- 1. Drop Composite Foreign Key on evidence
ALTER TABLE evidence DROP CONSTRAINT IF EXISTS fk_evidence_tenant_case;

-- 2. Drop Composite Unique Constraint on cases
ALTER TABLE cases DROP CONSTRAINT IF EXISTS uq_cases_tenant_case;

-- 3. Drop Underlying Unique Index
DROP INDEX CONCURRENTLY IF EXISTS idx_cases_tenant_case_unique;

COMMIT;

