-- Rollback for 053: restore the 051 body and drop the scope row guard.
drop trigger if exists a01_role_scope_row_authority on iam.membership_role_sites;
drop trigger if exists a01_role_scope_row_authority on iam.membership_role_org_units;
drop function if exists private.guard_role_scope_row_authority();
CREATE OR REPLACE FUNCTION private.guard_assigned_role_authority()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare p record;a text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
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
