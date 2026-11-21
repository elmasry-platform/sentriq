-- SENTRIQ Phase 1: remove legacy bypasses from operational structure paths.
begin;

-- Operational structure is part of Phase 1. Replace every permissive legacy
-- policy here; adding a stricter policy alongside an OR-combined permissive
-- policy would leave the Platform Operator/Superadmin bypass effective.
drop policy if exists org_read on core.org_units;
drop policy if exists org_insert on core.org_units;
drop policy if exists org_update on core.org_units;
drop policy if exists org_write on core.org_units;
drop policy if exists site_read on core.sites;
drop policy if exists site_insert on core.sites;
drop policy if exists site_update on core.sites;
create policy phase1_org_select on core.org_units for select to authenticated
 using(private.phase1_permission_allowed(tenant_id,'view_all',null,id,false)
    or private.phase1_permission_allowed(tenant_id,'scope_assign',null,id,true));
create policy phase1_org_insert on core.org_units for insert to authenticated
 with check(private.phase1_permission_allowed(tenant_id,'scope_assign',null,parent_id,true)
    or private.phase1_permission_allowed(tenant_id,'scope_assign',null,id,true));
create policy phase1_org_update on core.org_units for update to authenticated
 using(private.phase1_permission_allowed(tenant_id,'scope_assign',null,id,true))
 with check(private.phase1_permission_allowed(tenant_id,'scope_assign',null,id,true));
create policy phase1_site_select on core.sites for select to authenticated
 using(private.phase1_permission_allowed(tenant_id,'view_all',id,org_unit_id,false)
    or private.phase1_permission_allowed(tenant_id,'scope_assign',id,org_unit_id,true));
create policy phase1_site_insert on core.sites for insert to authenticated
 with check(private.phase1_permission_allowed(tenant_id,'scope_assign',id,org_unit_id,true));
create policy phase1_site_update on core.sites for update to authenticated
 using(private.phase1_permission_allowed(tenant_id,'scope_assign',id,org_unit_id,true))
 with check(private.phase1_permission_allowed(tenant_id,'scope_assign',id,org_unit_id,true));

commit;
