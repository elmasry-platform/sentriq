-- Audit scope distinguishes platform from tenant-owned scoped operations.
-- Site/Org/Task events still require the same tenant boundary.
begin;
alter table audit.events drop constraint events_scope_kind_check;
alter table audit.events add constraint events_scope_kind_check
 check(scope_kind in ('tenant','platform','site','org_unit','assigned_task','employees_default'));
alter table audit.events drop constraint audit_scope_consistent;
alter table audit.events add constraint audit_scope_consistent
 check((scope_kind='platform' and tenant_id is null) or (scope_kind<>'platform' and tenant_id is not null));
commit;
