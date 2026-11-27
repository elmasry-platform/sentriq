-- 055: a company Admin reads the site assignments (iam.site_access) of EMPLOYEE-level members of the same tenant.
-- Product decision as relayed by Main (not verified by me against the original): "he sees them normally".
-- Level comes only from iam.memberships.member_role, so a temporary permission, delegation or grant cannot widen it.
-- Never Superadmin rows, never other Admin rows, never another tenant. Own rows and Superadmin access are unchanged.
-- Read only: site_access_insert and site_access_update are not touched. Feeds api.v_memberships."siteIds".
-- Independent of 054 (the helper below does its own admin check and does not depend on memberships RLS).
-- Rollback: supabase/rollbacks/202611250055_admin_reads_employee_site_access.rollback.sql. Plain PostgreSQL. No data change.

create or replace function private.admin_can_read_employee_member(p_tenant_id uuid, p_membership_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1
     from iam.memberships a
     join core.tenants t on t.id = a.tenant_id
     join iam.memberships e on e.tenant_id = a.tenant_id
    where a.tenant_id = p_tenant_id
      and a.user_id = auth.uid()
      and a.member_role = 'company_admin' and a.status = 'active' and t.status = 'active'
      and e.id = p_membership_id and e.member_role = 'employee')
$$;
revoke all on function private.admin_can_read_employee_member(uuid, uuid) from public, anon;
grant execute on function private.admin_can_read_employee_member(uuid, uuid) to authenticated;

drop policy if exists site_access_read on iam.site_access;
create policy site_access_read on iam.site_access for select to authenticated
 using (private.can_manage_tenant(tenant_id)
        or (exists (select 1 from iam.memberships m
                     where m.id = site_access.membership_id and m.user_id = (select auth.uid())))
        or private.admin_can_read_employee_member(tenant_id, membership_id));
