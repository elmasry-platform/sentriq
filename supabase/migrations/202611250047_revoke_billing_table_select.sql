-- 047: remove direct table SELECT on core.invoices and core.payments from authenticated. Plain PostgreSQL.
-- Why: migration 002 granted SELECT on these tables and relied on RLS alone. The only permissive policy is
-- operator-only (invoices_read, payments_read) and migration 025 adds a restrictive policy that blocks operators,
-- so no signed-in user can read a row today. Nothing in the app reads them directly (the UI reads through
-- api.platform_read_company, a SECURITY DEFINER function owned by postgres, which keeps working). Removing the
-- privilege makes the denial a hard 42501 instead of "0 rows", and a future policy mistake can no longer expose billing data.
-- Not changed: RLS and policies, anon (already has no privilege), service_role, every other table, all functions.
-- Rollback: 047_rollback.sql.
revoke select on core.invoices, core.payments from authenticated;
