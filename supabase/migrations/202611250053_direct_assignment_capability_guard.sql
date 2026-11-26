-- 053: a direct INSERT into the role assignment tables now honors the same capability check as api.assign_membership_role.
-- Found in the audit: a company superadmin whose role_assignment capability is limited (superadmin_capability_limits
-- can_use=false or can_delegate=false) is refused by api.assign_membership_role (tenant_role_assignment_not_delegated)
-- but could INSERT directly into iam.membership_roles, membership_role_sites or membership_role_org_units, because the
-- table RLS only asks can_manage_tenant(). Direct writes stay allowed (the tests and the 048 guard classify them);
-- the three insert triggers now run the same phase1_can_manage check, with the same error names as the RPC.
-- Migrations (postgres session, no role) and platform operators are unchanged. api.assign_membership_role is the only
-- function that inserts into these tables, so no other write path changes.
-- Plain PostgreSQL: one function body replaced, one function and two triggers added, no data change.

CREATE OR REPLACE FUNCTION private.guard_assigned_role_authority()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare p record;a text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if not private.is_platform_operator() and exists(select 1 from iam.role_version_permissions q
     where q.role_version_id=new.role_version_id and q.scope_kind='tenant')
    and not private.phase1_can_manage(new.tenant_id,'role_assignment',new.membership_id,null,null) then
   raise exception 'tenant_role_assignment_not_delegated' using errcode='42501'; end if;
 if new.role_version_id is not null then
  for p in select * from iam.role_version_permissions where role_version_id=new.role_version_id loop
   if p.scope_kind='tenant' then
    if p.can_read or p.can_write then
     perform private.assert_permission_grantable(new.tenant_id,p.permission_key,p.can_write,null,null);
    end if;
    foreach a in array p.actions loop
     if a not in ('read','write') then perform private.assert_action_delegable(new.tenant_id,p.permission_key,a,null,null); end if;
    end loop;
   end if;
  end loop;
 end if;
 return new;
end $function$;

create or replace function private.guard_role_scope_row_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_member uuid;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if private.is_platform_operator() then return new; end if;
 select membership_id into v_member from iam.membership_roles where id=new.membership_role_id and tenant_id=new.tenant_id;
 if tg_table_name='membership_role_sites' then
  if not private.phase1_can_manage(new.tenant_id,'role_assignment',v_member,new.site_id,null) then
   raise exception 'site_role_assignment_scope_not_delegated' using errcode='42501'; end if;
 else
  if not private.phase1_can_manage(new.tenant_id,'role_assignment',v_member,null,new.org_unit_id) then
   raise exception 'org_role_assignment_scope_not_delegated' using errcode='42501'; end if;
 end if;
 return new;
end $$;
revoke all on function private.guard_role_scope_row_authority() from public, anon, authenticated, service_role;
drop trigger if exists a01_role_scope_row_authority on iam.membership_role_sites;
create trigger a01_role_scope_row_authority before insert on iam.membership_role_sites
 for each row execute function private.guard_role_scope_row_authority();
drop trigger if exists a01_role_scope_row_authority on iam.membership_role_org_units;
create trigger a01_role_scope_row_authority before insert on iam.membership_role_org_units
 for each row execute function private.guard_role_scope_row_authority();
