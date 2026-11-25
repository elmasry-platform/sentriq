-- Rollback for 047. Restores the grant made by migration 002. RLS and policies were never touched, so reads stay
-- blocked by policy (operator-only permissive plus the restrictive operator boundary).
grant select on core.invoices, core.payments to authenticated;
