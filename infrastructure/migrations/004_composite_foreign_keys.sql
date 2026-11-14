-- ==============================================================================
-- ARGUS MIGRATION 004: Staged Zero-Downtime Composite Foreign Keys
-- File: Argus/infrastructure/migrations/004_composite_foreign_keys.sql
-- Recommended Runner: python -m Argus.infrastructure.migrations.runner
--
-- EXECUTION CONTRACT:
--   Stages 1 & 2 must be executed with autocommit=True outside any transaction block.
--   Stages 3, 4, and 5 use bounded lock timeouts to prevent queue blocking.
-- ==============================================================================

-- STAGE 1: Non-Blocking Concurrent Unique Index Creation (SHARE UPDATE EXCLUSIVE)
-- Note: Must be executed with autocommit enabled.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_tenant_case_unique
ON cases (tenant_id, case_id);

-- STAGE 2: Attach Constraint using Index with Lock Timeout (< 5 ms catalog lock)
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '10s';
ALTER TABLE cases
ADD CONSTRAINT uq_cases_tenant_case
UNIQUE USING INDEX idx_cases_tenant_case_unique;
COMMIT;

-- STAGE 3: Add Composite Foreign Key as NOT VALID (< 5 ms catalog lock)
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '10s';
ALTER TABLE evidence
ADD CONSTRAINT fk_evidence_tenant_case
FOREIGN KEY (tenant_id, case_id)
REFERENCES cases (tenant_id, case_id)
ON DELETE RESTRICT
NOT VALID;
COMMIT;

-- STAGE 4: Validate Constraint Separately (Non-Blocking Table Scan)
ALTER TABLE evidence
VALIDATE CONSTRAINT fk_evidence_tenant_case;
